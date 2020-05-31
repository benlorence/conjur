require 'command_class'

module Authentication
  module AuthnAzure

    Log = LogMessages::Authentication::AuthnAzure
    Err = Errors::Authentication::AuthnAzure
    # Possible Errors Raised: RoleNotFound, InvalidApplicationIdentity, XmsMiridParseError,
    # MissingProviderFieldsInXmsMirid, MissingConstraint,
    # IllegalConstraintCombinations

    AZURE_RESOURCE_TYPES = %w(subscription-id resource-group user-assigned-identity system-assigned-identity)

    ValidateApplicationIdentity = CommandClass.new(
      dependencies: {
        role_class:                 ::Role,
        resource_class:             ::Resource,
        application_identity_class: ApplicationIdentity,
        logger:                     Rails.logger
      },
      inputs:       %i(account service_id username xms_mirid_token_field oid_token_field)
    ) do

      def call
        extract_application_identity_from_role
        validate_application_identity_configuration
        validate_application_identity_matches_request
      end

      private

      def extract_application_identity_from_role
        application_identity
      end

      def application_identity
        @application_identity ||= @application_identity_class.new(
          role_annotations: role_annotations,
          service_id:       @service_id,
          azure_resource_types: AZURE_RESOURCE_TYPES,
          logger:           @logger
        )
      end

      def validate_application_identity_configuration
        validate_permitted_scope
        validate_required_constraints_exist
        validate_constraint_combinations
      end

      # validating that the annotations listed for the Conjur resource align with the permitted Azure constraints
      def validate_permitted_scope
        validate_prefixed_permitted_annotations("authn-azure/")
        validate_prefixed_permitted_annotations("authn-azure/#{@service_id}/")
      end

      # check if annotations with the given prefix is part of the permitted list
      def validate_prefixed_permitted_annotations prefix
        @logger.debug(LogMessages::Authentication::ValidatingAnnotationsWithPrefix.new(prefix))

        prefixed_annotations(prefix).each do |annotation|
          annotation_name = annotation[:name]
          next if prefixed_permitted_constraints(prefix).include?(annotation_name)
          raise Err::ConstraintNotSupported.new(annotation_name.gsub(prefix, ""), AZURE_RESOURCE_TYPES)
        end
      end

      def prefixed_annotations prefix
        role_annotations.select do |a|
          annotation_name = a.values[:name]

          annotation_name.start_with?(prefix) &&
            # verify we take only annotations from the same level
            annotation_name.split('/').length == prefix.split('/').length + 1
        end
      end

      # add prefix to all permitted constraints
      def prefixed_permitted_constraints prefix
        AZURE_RESOURCE_TYPES.map { |k| "#{prefix}#{k}" }
      end

      def validate_required_constraints_exist
        validate_resource_constraint_exists "subscription-id"
        validate_resource_constraint_exists "resource-group"
      end

      def validate_resource_constraint_exists resource_type
        resource = application_identity.resources.find { |a| a.type == resource_type }
        raise Err::RoleMissingConstraint, resource_type unless resource
      end

      # validates that the application identity doesn't include logical resource constraint
      # combinations (e.g user_assigned_identity & system_assigned_identity)
      def validate_constraint_combinations
        identifiers = %w(user-assigned-identity system-assigned-identity)

        identifiers_constraints = application_identity.resources.map(&:type) & identifiers
        unless identifiers_constraints.length <= 1
          raise Errors::Authentication::IllegalConstraintCombinations, identifiers_constraints
        end
      end

      # xms_mirid is a term in Azure to define a claim that describes the resource that holds the encoding of the instance's
      # among other details the subscription_id, resource group, and provider identity needed for authorization.
      # xms_mirid is one of the fields in the JWT token. This function will extract the relevant information from
      # xms_mirid claim and populate a representative hash with the appropriate fields.
      def extract_resources_from_token
        @resources_from_token = [
          AzureResource.new(
            type: "subscription-id",
            value: xms_mirid.subscriptions
          ),
          AzureResource.new(
            type: "resource-group",
            value: xms_mirid.resource_groups
          )
        ]

        # determine which identity is provided in the token. If the token is
        # issued to a user-assigned identity then we take the identity name.
        # If the token is issued to a system-assigned identity then we take the
        # Object ID of the token.
        if xms_mirid.providers.include? "Microsoft.ManagedIdentity"
          @resources_from_token.push(
            AzureResource.new(
              type: "user-assigned-identity",
              value: xms_mirid.providers.last
            )
          )
        else
          @resources_from_token.push(
            AzureResource.new(
              type: "system-assigned-identity",
              value: @oid_token_field
            )
          )
        end
        @logger.debug(Log::ExtractedApplicationIdentityFromToken.new)
      end

      def xms_mirid
        @xms_mirid ||= XmsMirid.new(@xms_mirid_token_field)
      end

      def validate_application_identity_matches_request
        extract_resources_from_token

        application_identity.resources.each do |resource_from_role|
          @resources_from_token.each do |resource_from_token|
            if resource_from_token.type == resource_from_role.type &&
              resource_from_token.value != resource_from_role.value
                raise Err::InvalidApplicationIdentity, resource_from_role.type
            end
          end
        end
        @logger.debug(LogMessages::Authentication::ValidatedApplicationIdentity.new)
      end

      def role
        return @role if @role

        @role = @resource_class[role_id]
        raise Errors::Authentication::Security::RoleNotFound, role_id unless @role
        @role
      end

      def role_annotations
        @role_annotations ||= role.annotations
      end

      def role_id
        @role_id ||= @role_class.roleid_from_username(@account, @username)
      end
    end
  end
end
