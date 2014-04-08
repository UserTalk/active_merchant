# coding: utf-8
require 'rexml/document'
require "digest/sha2"

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:

    # = Payfort DirectLink integration
    # Based off Ogone DirectLink
    class PayfortGateway < Gateway
      self.test_url = 'https://secure.payfort.com/ncol/test'
      self.live_url = 'https://secure.payfort.com/ncol/prod'

      self.supported_countries = %w(US CA GB DE DK EG AE)
      self.money_format = :cents
      self.default_currency = 'USD'
      self.supported_cardtypes = [:visa, :master, :maestro]

      self.homepage_url = 'http://www.payfort.com/'
      self.display_name = 'Payfort Payments'

      OPERS = {
        :refund => 'RFD',
        :authorize => 'RES',
        :direct_sale => 'SAL',
        :void_authorization => 'DES'
      }

      AVS = {
        'OK' => 'M',
        'KO' => 'N',
        'NO' => 'R'
      }

      CVC = {
        'OK' => 'M',
        'KO' => 'N',
        'NO' => 'P'
      }

      def initialize(options={})
        requires!(options, :account_ref, :api_user, :api_password, :sha_passphrase, :sha)
        super
      end

      def purchase(money, payment, options={})
        post = {}
        add_order(post, money, options)
        add_customer(post, options)
        add_payment(post, payment, options)
        add_address(post, options)
        commit(OPERS[:direct_sale], post)
      end

      def authorize(money, payment, options={})
        post = {}
        add_order(post, money, options)
        add_customer(post, options)
        add_payment(post, payment, options)
        add_address(post, options)
        commit(OPERS[:authorize], post)
      end

      def capture(money, authorization, options={})
        post = {}
        add_authorization(post, reference_from(authorization))
        add_order(post, money, options)
        add_customer(post, options)
        commit(OPERS[:direct_sale], post)
      end

      def void(authorization)
        post = {}
        add_authorization(post, reference_from(authorization))
        commit(OPERS[:void_authorization], post)
      end

      def refund(money, authorization, options={})
        post = {}
        add_authorization(post, reference_from(authorization))
        add_money(post, money, options)
        commit(OPERS[:refund], post)
      end

      def store(card, options={})
        options.merge!(:alias_operation => 'BYPSP') unless options[:billing_id]
        response = authorize(1, card, options)
        void(response.authorization) if response.success?
        response
      end


      private

      def add_money(post, money, options)
        add_pair post, 'AMOUNT', amount(money)
        add_pair post, 'CURRENCY', (options[:currency] || @options[:currency] || currency(money))
      end

      def add_order(post, money, options)
        add_money(post, money, options)
        add_pair post, 'ORDERID', (options[:order_id] || generate_unique_id)
        add_pair post, 'COM', options[:description]
      end

      def add_customer(post, options)
        add_pair post, 'EMAIL', options[:customer_email]
        add_pair post, 'REMOTE_ADDR', options[:customer_ip]
      end

      def add_payment(post, payment, options)
        if payment.is_a?(CreditCard)
          add_card(post, payment)
          add_pair post, 'ALIAS', options[:alias]
        else
          add_pair post, 'ALIAS', payment
        end
        add_pair post, 'ALIASOPERATION', options[:alias_operation]
        add_pair post, 'ECI', options[:eci].to_s || '9'
      end

      def add_card(post, card)
        add_pair post, 'CARDNO', card.number
        add_pair post, 'CN', card.name
        add_pair post, 'ED', "%02d%02s" % [creditcard.month, creditcard.year.to_s[-2..-1]]
        add_pair post, 'CVC', card.verification_value
      end

      def add_address(post, options)
        return unless options[:billing_address]

        add_pair post, 'OWNERADDRESS', options[:billing_address][:address]
        add_pair post, 'OWNERZIP', options[:billing_address][:zip]
        add_pair post, 'OWNERTOWN', options[:billing_address][:city]
        add_pair post, 'OWNERCTY', options[:billing_address][:country]
        add_pair post, 'OWNERTELNO', options[:billing_address][:phone]
      end

      def reference_from(authorization)
        authorization.split(";").first
      end

      def convert_attributes_to_hash(rexml_attributes)
        response_hash = {}
        rexml_attributes.each do |key, value|
          response_hash[key] = value
        end
        response_hash
      end

      def parse(body)
        ncresponse = REXML::Document.new(body).root.elements["ncresponse"]
        convert_attributes_to_hash(ncresponse.attributes)
      end

      def commit(action, params)
        add_pair params, 'PSPID',  @options[:account_ref]
        add_pair params, 'USERID', @options[:api_user]
        add_pair params, 'PSWD',   @options[:api_password]
        add_pair params, 'WITHROOT', 'Y'
        add_pair params, 'OPERATION', action

        response = parse(ssl_post(url(params['PAYID']), post_data(params)))
        options = {
          :authorization => [response["PAYID"], action].join(';'),
          :test => test?,
          :avs_result => { :code => AVS[response['AAVCHECK']] },
          :cvc_result => CVC[response['CVCCHECK']]
        }

        response = Response.new(successful?(response), message_from(response), response, options)
        response.instance_eval do
          def payid
            @params['PAYID']
          end

          def order_id
            @params['orderID']
          end

          def alias
            @params['ALIAS']
          end
        end
        response
      end

      def sign(params)
        string_to_digest = if @options[:sha]
          params.sort { |a, b| a[0].upcase <=> b[0].upcase }.map { |k, v| "#{k.upcase}=#{v}" }.join(@options[:sha_passphrase])
        else
          %w[ORDERID AMOUNT CURRENCY CARDNO PSPID OPERATION ALIAS].map { |key| params[key] }.join
        end
        string_to_digest << @options[:sha_passphrase]

        "Digest::#{@options[:sha].upcase}".constantize.hexdigest(string_to_digest)
      end

      def successful?(response)
        response["NCERROR"] == "0"
      end

      def message_from(response)
        if successful?(response)
          "Transaction successful"
        else
          format_error_message(response["NCERRORPLUS"])
        end
      end

      def format_error_message(message)
        raw_message = message.to_s.strip
        case raw_message
        when /\|/
          raw_message.split("|").join(", ").capitalize
        when /\//
          raw_message.split("/").first.to_s.capitalize
        else
          raw_message.to_s.capitalize
        end
      end

      def authorization_from(response)
        response[:authorization]
      end

      def add_pair(post, key, value)
        post[key] = value if !value.blank?
      end
      
      def url(payid)
        (test? ? test_url : live_url) + (payid ? "/maintenancedirect.asp" : "/orderdirect.asp")
      end

      def post_data(params)
        add_pair params, 'SHASIGN', sign(params)
        params.to_query
      end
    end
  end
end