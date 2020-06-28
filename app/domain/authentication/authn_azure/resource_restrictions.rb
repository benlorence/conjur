module Authentication
  module AuthnAzure

    # This class represents the restrictions that are set on a Conjur host regarding
    # the Azure resources that it can authenticate with Conjur from.
    # It consists a list of AzureResource objects which represent the resource
    # restriction that need to be met in an authentication request.
    #
    # For example, if `resources` includes the AzureResource:
    #   - type: "subscription-id"
    #   - value: "some-subscription-id"
    #
    # then this Conjur host can authenticate with Conjur only with an Azure AD
    # token that was granted to an Azure resource that is part of the "some-subscription-id"
    # subscription
    class ResourceRestrictions

      attr_reader :resources

      AZURE_RESOURCE_TYPES = %w(subscription-id resource-group user-assigned-identity system-assigned-identity)

      def initialize(role_annotations:, service_id:, logger:)
        @role_annotations = role_annotations
        @service_id       = service_id
        @logger           = logger

        init_resources
      end

      # Verify that the Resource Restrictions were configured correctly.
      # Ideally this validation would have happened in the host creation but we
      # don't have that mechanism so we validate it here.
      def valid_configuration?
        validate_permitted_scope
        validate_required_constraints_exist
        validate_constraint_combinations
      end

      def match? resources_from_request
        @resources.each do |resource_from_role|
          resource_from_request = resources_from_request.find { |a| a.type == resource_from_role.type }
          if resource_from_request.value != resource_from_role.value
            raise Errors::Authentication::AuthnAzure::InvalidResourceRestrictions, resource_from_role.type
          end
        end
      end

      private

      def init_resources
        @resources = AZURE_RESOURCE_TYPES.each_with_object([]) do |resource_type, resources|
          resource_value = resource_value(resource_type)
          if resource_value
            resources.push(
              AzureResource.new(
                type: resource_type,
                value: resource_value
              )
            )
          end
        end
      end

      # check the `service-id` specific resource first to be more granular
      def resource_value resource_type
        annotation_value("authn-azure/#{@service_id}/#{resource_type}") ||
          annotation_value("authn-azure/#{resource_type}")
      end

      def annotation_value name
        annotation = @role_annotations.find { |a| a.values[:name] == name }

        # return the value of the annotation if it exists, nil otherwise
        if annotation
          @logger.debug(LogMessages::Authentication::RetrievedAnnotationValue.new(name))
          annotation[:value]
        end
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
          raise Errors::Authentication::ConstraintNotSupported.new(
            annotation_name.gsub(prefix, ""),
            AZURE_RESOURCE_TYPES
          )
        end
      end

      def prefixed_annotations prefix
        @role_annotations.select do |a|
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
        resource = @resources.find { |a| a.type == resource_type }
        unless resource
          raise Errors::Authentication::AuthnAzure::RoleMissingConstraint, resource_type
        end
      end

      # validates that the resource restrictions do include logical resource constraint
      # combinations (e.g user_assigned_identity & system_assigned_identity)
      def validate_constraint_combinations
        identifiers = %w(user-assigned-identity system-assigned-identity)

        identifiers_constraints = @resources.map(&:type) & identifiers
        unless identifiers_constraints.length <= 1
          raise Errors::Authentication::IllegalConstraintCombinations, identifiers_constraints
        end
      end
    end
  end
end
