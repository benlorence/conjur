module Authentication
  module AuthnK8s

    class K8sResource
      attr_reader :type, :value

      def initialize(type:, value:)
        @type = type
        @value = value
      end
    end
  end
end
