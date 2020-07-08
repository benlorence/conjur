
# frozen_string_literal: true

require 'spec_helper'
RSpec.describe 'Authentication::Authn::Login' do
  let(:input) do
    ::Authentication::AuthenticatorInput.new(
      authenticator_name: 'authn',
      service_id:         'service',
      account:            'account',
      username:           'username',
      credentials:        'creds',
      client_ip:          '127.0.0.1',
      request:            nil
    )
  end

  let(:mocked_role) { double("Role") }
  def mocked_role
    double('Role').tap do |role|
      allow(role).to receive(:roleid_from_username)
                       .and_return("account:user:username")
    end
  end

  let(:mocked_credentials) { double("Credentials") }
  def mocked_credentials
    double('Credentials').tap do |creds|
      allow(creds).to receive(:[]).and_return(creds)
      allow(creds).to receive(:authenticate).and_return(true)
      allow(creds).to receive(:api_key).and_return('valid_api_key')
    end
  end

  let(:mocked_role_not_found_credentials) { double("Credentials") }
  def mocked_role_not_found_credentials
    double('Credentials').tap do |creds|
      allow(creds).to receive(:[]).and_return(nil)
    end
  end

  context "An authn/login" do
    context "that receives a login input" do
      context "with a valid credentials" do
        subject do
          ::Authentication::Authn::Login.new(
              role_cls:  mocked_role,
              credentials_cls: mocked_credentials
          )
          .call(authenticator_input: input)
        end

        it "does not raise an error" do
          expect {subject}.to_not raise_error
        end

        it "should return a non nil value" do
          expect(subject).not_to eq(nil)
        end
      end
      context "with role not found" do
        subject do
          ::Authentication::Authn::Login.new(
              role_cls:  mocked_role,
              credentials_cls: mocked_role_not_found_credentials
            )
            .call(authenticator_input: input)
        end

        it "does not raise an error" do
          expect {subject}.to_not raise_error
        end

        it "should return nil" do
          expect(subject).to eq(nil)
        end
      end
    end
  end
end