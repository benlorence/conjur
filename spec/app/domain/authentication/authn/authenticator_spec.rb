# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Authentication::Authn::Authenticator' do
  let(:input) do
    ::Authentication::AuthenticatorInput.new(
      authenticator_name: 'authn',
      service_id:         'my-service',
      account:            'my-acct',
      username:           'alice',
      credentials:        'credentials',
      client_ip:          '127.0.0.1',
      request:            nil
    )
  end
  let(:mocked_role_cls) { double("Role") }
  def mocked_role_cls
    double('Role').tap do |role|
      allow(role).to receive(:roleid_from_username).and_return('roleid')
    end
  end

  let(:mocked_credentials) { double("Credentials") }
  def mocked_credentials
    double('Credentials').tap do |creds|
      allow(creds).to receive(:[]).and_return(creds)
      allow(creds).to receive(:authenticate).and_return(creds)
      allow(creds).to receive(:api_key).and_return('api_key')
    end
  end

  context "An Authn authenticator" do
    context "that receives a login request" do
      context "with a valid username" do
        subject do
            ::Authentication::Authn::Authenticator.new(
              ::Authentication::Authn::Login.new(
                role_cls:         mocked_role_cls,
                credentials_cls:  mocked_credentials,)
            ).login(input)
        end

        it "does not raise an error" do
          expect {subject}.to_not raise_error
        end

        it "returns an api key" do
           expect(subject).to eq('api_key')
        end
      end
    end
  end
end
