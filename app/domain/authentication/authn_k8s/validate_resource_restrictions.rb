require 'forwardable'
require 'command_class'

module Authentication
  module AuthnK8s

    Err ||= Errors::Authentication::AuthnK8s
    # Possible Errors Raised: NamespaceMismatch, ContainerNotFound,
    # K8sResourceNotFound, IllegalConstraintCombinations,
    # ScopeNotSupported, InvalidHostId, RoleMissingConstraint

    K8S_RESOURCE_TYPES = %w(namespace service-account pod deployment stateful-set deployment-config)

    ValidateResourceRestrictions ||= CommandClass.new(
      dependencies: {
        resource_class:              ::Resource,
        k8s_resolver:                K8sResolver,
        k8s_object_lookup_class:     K8sObjectLookup,
        resource_restrictions_class: ResourceRestrictions,
        logger:                      Rails.logger
      },
      inputs:       %i(host_id host_annotations account service_id spiffe_id authentication_container_name_annotation)
    ) do

      def call
        extract_resource_restrictions_from_role
        validate_resource_restrictions_configuration
        validate_resource_restrictions_matches_request
      end

      private

      def extract_resource_restrictions_from_role
        resource_restrictions
      end

      def resource_restrictions
        @resource_restrictions ||= @resource_restrictions_class.new(
          host_id:          host_id_suffix,
          host_annotations: @host_annotations,
          service_id:       @service_id,
          resource_restrictions_in_annotations: resource_restrictions_in_annotations?,
          k8s_resource_types: K8S_RESOURCE_TYPES,
          logger: @logger
        )
      end

      def validate_resource_restrictions_configuration
        validate_permitted_scope
        validate_required_constraints_exist
        validate_constraint_combinations
      end

      # If the resource restrictions are defined in:
      #   - annotations: validates that all the constraints are
      #                  valid (e.g there is no "authn-k8s/blah" annotation)
      #   - host id: validates that the host-id has 3 parts and that the given
      #              constraint is valid (e.g the host id is not
      #              "namespace/blah/some-value")
      def validate_permitted_scope
        resource_restrictions_in_annotations? ? validate_permitted_annotations : validate_host_id
      end

      # We expect the resource restrictions to be defined by the host's annotations
      # if any of the constraint annotations is present.
      def resource_restrictions_in_annotations?
        @resource_restrictions_in_annotations ||= K8S_RESOURCE_TYPES.any? do |resource_type|
          resource_from_annotation(resource_type)
        end
      end

      def validate_permitted_annotations
        validate_prefixed_permitted_annotations("authn-k8s/")
        validate_prefixed_permitted_annotations("authn-k8s/#{@service_id}/")
      end

      def validate_prefixed_permitted_annotations prefix
        @logger.debug(LogMessages::Authentication::ValidatingAnnotationsWithPrefix.new(prefix))

        prefixed_k8s_annotations(prefix).each do |annotation|
          annotation_name = annotation[:name]
          next if prefixed_permitted_annotations(prefix).include?(annotation_name)
          raise Err::ScopeNotSupported.new(annotation_name.gsub(prefix, ""), K8S_RESOURCE_TYPES)
        end
      end

      def prefixed_k8s_annotations prefix
        @host_annotations.select do |a|
          annotation_name = a.values[:name]

          # Calculate the granularity level of the annotation.
          # For example, the annotation "authn-k8s/namespace" is in the general
          # level, and applies to every host that tries to authenticate with the
          # k8s authenticator, regardless of the service id.
          # The annotation "authn-k8s/#{@service_id}/namespace" is on the
          # service-id level, and applies only to hosts trying to authenticate
          # with the authenticator "authn-k8s/#{@service_id}".
          annotation_granularity_level = annotation_name.split('/').length
          prefix_granularity_level     = prefix.split('/').length

          annotation_name.start_with?(prefix) &&
            # Verify we take only annotations from the same level.
            annotation_granularity_level == prefix_granularity_level + 1
        end
      end

      def prefixed_permitted_annotations prefix
        permitted_annotations.map { |k| "#{prefix}#{k}" }
      end

      def permitted_annotations
        @permitted_annotations ||= K8S_RESOURCE_TYPES | [@authentication_container_name_annotation]
      end

      def validate_host_id
        @logger.debug(Log::ValidatingHostId.new(@host_id))

        valid_host_id = host_id_suffix.length == 3
        raise Err::InvalidHostId, @host_id unless valid_host_id

        return if host_id_namespace_scoped?

        resource_type       = host_id_suffix[-2]
        unless underscored_k8s_resource_types.include?(resource_type)
          raise Err::ScopeNotSupported.new(resource_type, underscored_k8s_resource_types)
        end
      end

      def host_id_namespace_scoped?
        host_id_suffix[-2] == '*' && host_id_suffix[-1] == '*'
      end

      def validate_required_constraints_exist
        validate_resource_constraint_exists "namespace"
      end

      def validate_resource_constraint_exists resource_type
        resource = resource_restrictions.resources.find { |a| a.type == resource_type }
        raise Err::RoleMissingConstraint, resource_type unless resource
      end

      # Validates that the resource restrictions don't include logical resource constraint
      # combinations (e.g deployment & deploymentConfig)
      def validate_constraint_combinations
        identifiers = %w(deployment deployment-config stateful-set)

        identifiers_constraints = resource_restrictions.resources.map(&:type) & identifiers
        unless identifiers_constraints.length <= 1
          raise Errors::Authentication::IllegalConstraintCombinations, identifiers_constraints
        end
      end

      def resource_from_annotation resource_type
        annotation_value("authn-k8s/#{@service_id}/#{resource_type}") ||
          annotation_value("authn-k8s/#{resource_type}")
      end

      def annotation_value name
        annotation = @host_annotations.find { |a| a.values[:name] == name }

        # return the value of the annotation if it exists, nil otherwise
        if annotation
          @logger.debug(LogMessages::Authentication::RetrievedAnnotationValue.new(name))
          annotation[:value]
        end
      end

      def validate_resource_restrictions_matches_request
        resource_restrictions.resources.each do |resource_from_role|
          resource_type   = underscored_k8s_resource_type(resource_from_role.type)
          resource_value   = resource_from_role.value
          if resource_type == "namespace"
            unless resource_value == @spiffe_id.namespace
              raise Err::NamespaceMismatch.new(@spiffe_id.namespace, resource_value)
            end
            next
          end

          resource_from_k8s = k8s_resource_object(
            resource_type,
            resource_value,
            @spiffe_id.namespace
          )

          unless resource_from_k8s
            raise Err::K8sResourceNotFound.new(resource_type, resource_value, @spiffe_id.namespace)
          end

          @k8s_resolver
            .for_resource(resource_type)
            .new(
              resource_from_k8s,
              pod,
              k8s_object_lookup
            )
            .validate_pod
        end
        @logger.debug(LogMessages::Authentication::ValidatedResourceRestrictions.new)
      end

      def k8s_object_lookup
        @k8s_object_lookup ||= @k8s_object_lookup_class.new(webservice)
      end

      def k8s_resource_object resource_type, resource_value, namespace
        @k8s_resource_object = k8s_object_lookup.find_object_by_name(
          resource_type,
          resource_value,
          namespace
        )
      end

      def pod
        @pod ||= k8s_object_lookup.pod_by_name(pod_name, pod_namespace)
      end

      def pod_name
        @spiffe_id.name
      end

      def pod_namespace
        @spiffe_id.namespace
      end

      # @return The Conjur resource for the webservice.
      def webservice
        @webservice ||= ::Authentication::Webservice.new(
          account:            @account,
          authenticator_name: 'authn-k8s',
          service_id:         @service_id
        )
      end

      # Return the last three parts of the host id, which consist of the host's
      # resource restrictions
      def host_id_suffix
        @host_id_suffix ||= hostname.split('/').last(3)
      end

      # Return the last part of the host id (which is the actual hostname).
      # The host id is build as "account_name:kind:identifier" (e.g "org:host:some_hostname").
      def hostname
        @hostname ||= @host_id.split(':')[2]
      end

      def underscored_k8s_resource_types
        @underscored_resource_types ||= K8S_RESOURCE_TYPES.map { |resource_type| underscored_k8s_resource_type(resource_type) }
      end

      def underscored_k8s_resource_type resource_type
        resource_type.tr('-', '_')
      end
    end
  end
end
