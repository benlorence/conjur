# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Authentication::Authn::Login' do
  include_context "authn setup"

  context "An An Authn authenticator" do
    context "that receives login request" do
      context "with a valid credentials" do
        subject do
          ::Authentication::Authn::Login.new(
              role_cls:  mocked_role,
              credentials_cls: mocked_credentials
          ).call(
            authenticator_input: input
          )
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
