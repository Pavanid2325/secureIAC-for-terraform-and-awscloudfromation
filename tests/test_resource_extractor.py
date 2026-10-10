from src.parser.cloudformation_parser import CloudFormationParser


def test_security_properties_are_extracted_and_unknowns_preserved():
    parsed = CloudFormationParser().parse_text(
        """
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Condition: CreateDb
    DependsOn: Network
    Metadata:
      Owner: security
    CreationPolicy:
      ResourceSignal:
        Count: 1
    UpdatePolicy:
      AutoScalingRollingUpdate: {}
    Properties:
      StorageEncrypted: false
      CustomFutureProperty: kept
""",
        suffix=".yaml",
    )
    resource = parsed.resources[0]

    assert resource.condition == "CreateDb"
    assert resource.depends_on == "Network"
    assert resource.metadata["Owner"] == "security"
    assert resource.properties["CustomFutureProperty"] == "kept"
    assert resource.security_properties["StorageEncrypted"] is False
