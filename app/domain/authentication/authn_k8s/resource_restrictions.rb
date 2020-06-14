# frozen_string_literal: true

module Authentication
  module AuthnK8s

    # This class represents the restrictions that are set on a Conjur host regarding
    # the K8s resources that it can authenticate with Conjur from.
    # It consists a list of K8sResource objects which represent the resource
    # restriction that need to be met in an authentication request.
    #
    # For example, if `resources` includes the K8sResource:
    #   - type: "namespace"
    #   - value: "some-namespace"
    #
    # then this Conjur host can authenticate with Conjur only from a pod that is
    # part of the namespace "some-namespace"
    class ResourceRestrictions

      attr_reader :resources
      
      def initialize(host_id:, host_annotations:, service_id:, resource_restrictions_in_annotations:, k8s_resource_types:, logger:)
        @host_id          = host_id
        @host_annotations = host_annotations
        @service_id       = service_id
        @resource_restrictions_in_annotations = resource_restrictions_in_annotations
        @k8s_resource_types = k8s_resource_types
        @logger           = logger

        init_resources
      end

      private

      def init_resources
        @resources = @k8s_resource_types.each_with_object([]) do |resource_type, resources|
          resource_value = resource_value(resource_type)
          if resource_value
            resources.push(
              K8sResource.new(
                type: resource_type,
                value: resource_value
              )
            )
          end
        end
      end

      def resource_value resource_type
        @resource_restrictions_in_annotations ? resource_from_annotation(resource_type) : resource_from_id(underscored_resource_type(resource_type))
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

      def resource_from_id resource_type
        return @host_id[-3] if resource_type == "namespace"
        @host_id[-2] == resource_type ? @host_id[-1] : nil
      end

      def underscored_resource_type resource_type
        resource_type.tr('-', '_')
      end
    end
  end
end
