module Authentication
  module AuthnK8s

    Log = LogMessages::Authentication
    Err = Errors::Authentication
    # Possible Errors Raised: MissingNamespaceConstraint, IllegalConstraintCombinations,
    # ScopeNotSupported, InvalidHostId

    # This class defines an application identity of a given conjur host.
    # The constructor initializes an ApplicationIdentity object and validates that
    # it is configured correctly.
    # The difference between the validation in this constructor and
    # the validation in ValidateApplicationIdentity is that here we validate that
    # the application identity is configured correctly, and thus is a valid application
    # identity. In ValidateApplicationIdentity we validate that the defined application
    # identity is actually the correct one in kubernetes.
    # For example, an application identity `some-namepsace/blah/some-value` is not
    # valid and will fail the validation here. However, an application identity
    # `some-namespace/service-account/some-value` is a valid application identity
    # and will pass the validation here. If the host is actually running from
    # a pod with service account `some-other-value` then it will fail the
    # validation of ValidateApplicationIdentity
    class ApplicationIdentity

      def initialize(host_id:, host_annotations:, service_id:)
        @host_id          = host_id
        @host_annotations = host_annotations
        @service_id       = service_id

        validate
      end

      def namespace
        @namespace ||= application_identity_in_annotations? ? constraint_from_annotation("namespace") : host_id_suffix[-3]
      end

      def constraints
        @constraints ||= {
          pod:               constraint_value("pod"),
          service_account:   constraint_value("service_account"),
          deployment:        constraint_value("deployment"),
          deployment_config: constraint_value("deployment_config"),
          stateful_set:      constraint_value("stateful_set")
        }.compact
      end

      def container_name
        annotation_name = "authentication-container-name"
        annotation_value("authn-k8s/#{@service_id}/#{annotation_name}") ||
          annotation_value("authn-k8s/#{annotation_name}") ||
          annotation_value("kubernetes/#{annotation_name}") ||
          "authenticator"
      end

      # returns true if the only constraint is on the namespace, false otherwise
      def namespace_scoped?
        constraints.empty?
      end

      private

      # Validates that the application identity is defined correctly
      def validate
        validate_permitted_scope

        # validate that a constraint exists on the namespace
        raise Err::AuthnK8s::MissingNamespaceConstraint unless namespace

        validate_constraint_combinations
      end

      # If the application identity is defined in:
      #   - annotations: validates that all the constraints are
      #                  valid (e.g there is no "authn-k8s/blah" annotation)
      #   - host id: validates that the host-id has 3 parts and that the given
      #              constraint is valid (e.g the host id is not
      #              "namespace/blah/some-value")
      def validate_permitted_scope
        application_identity_in_annotations? ? validate_permitted_annotations : validate_host_id
      end

      # Validates that the application identity doesn't include logical constraint
      # combinations (e.g deployment & deploymentConfig)
      def validate_constraint_combinations
        controllers = %i(deployment deployment_config stateful_set)

        controller_constraints = constraints.keys & controllers
        raise Err::IllegalConstraintCombinations, controller_constraints unless controller_constraints.length <= 1
      end

      def constraint_value constraint_name
        application_identity_in_annotations? ? constraint_from_annotation(annotation_type_constraint(constraint_name)) : constraint_from_id(constraint_name)
      end

      def constraint_from_annotation constraint_name
        annotation_value("authn-k8s/#{@service_id}/#{constraint_name}") ||
          annotation_value("authn-k8s/#{constraint_name}")
      end

      # gets value for annotations for name inputed as key
      def annotation_value name
        annotation = @host_annotations.find { |a| a.values[:name] == name }

        # return the value of the annotation if it exists, nil otherwise
        if annotation
          Rails.logger.debug(Log::RetrievedAnnotationValue.new(name))
          annotation[:value]
        end
      end

      def constraint_from_id constraint_name
        host_id_suffix[-2] == constraint_name ? host_id_suffix[-1] : nil
      end

      def host_id_suffix
        @host_id_suffix ||= hostname.split('/').last(3)
      end

      # Return the last part of the host id (which is the actual hostname).
      # The host id is build as "account_name:kind:identifier" (e.g "org:host:some_hostname").
      def hostname
        @hostname ||= @host_id.split(':')[2]
      end

      def validate_permitted_annotations
        validate_prefixed_permitted_annotations("authn-k8s/")
        validate_prefixed_permitted_annotations("authn-k8s/#{@service_id}/")
      end

      def validate_prefixed_permitted_annotations prefix
        Rails.logger.debug(Log::ValidatingAnnotationsWithPrefix.new(prefix))

        prefixed_k8s_annotations(prefix).each do |annotation|
          annotation_name = annotation[:name]
          next if prefixed_permitted_annotations(prefix).include?(annotation_name)
          raise Err::AuthnK8s::ScopeNotSupported.new(annotation_name.gsub(prefix, ""), annotation_type_constraints)
        end
      end

      def prefixed_k8s_annotations prefix
        @host_annotations.select do |a|
          annotation_name = a.values[:name]

          annotation_name.start_with?(prefix) &&
            # verify we take only annotations from the same level
            annotation_name.split('/').length == prefix.split('/').length + 1
        end
      end

      def prefixed_permitted_annotations prefix
        permitted_annotations.map { |k| "#{prefix}#{k}" }
      end

      def validate_host_id
        Rails.logger.debug(Log::AuthnK8s::ValidatingHostId.new(@host_id))

        valid_host_id = host_id_suffix.length == 3
        raise Err::AuthnK8s::InvalidHostId, @host_id unless valid_host_id

        return if host_id_namespace_scoped?

        constraint       = host_id_suffix[-2]
        valid_constraint = permitted_constraints.include?(constraint)
        raise Err::AuthnK8s::ScopeNotSupported.new(constraint, permitted_constraints) unless valid_constraint
      end

      def permitted_constraints
        @permitted_constraints ||= %w(
          namespace service_account pod deployment stateful_set deployment_config
        )
      end

      def permitted_annotations
        @permitted_annotations ||= annotation_type_constraints << "authentication-container-name"
      end

      def annotation_type_constraints
        @annotation_type_constraints ||= permitted_constraints.map { |constraint| annotation_type_constraint(constraint) }
      end

      def annotation_type_constraint constraint
        constraint.tr('_', '-')
      end

      def application_identity_in_annotations?
        @application_identity_in_annotations ||= @host_annotations.select { |a| a.values[:name].start_with?("authn-k8s/") }.any?
      end

      def host_id_namespace_scoped?
        host_id_suffix[-2] == '*' && host_id_suffix[-1] == '*'
      end
    end
  end
end
