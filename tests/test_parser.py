import pytest

from src.parser.cloudformation_parser import CloudFormationParseError, CloudFormationParser


def test_yaml_parsing_preserves_intrinsics():
    parsed = CloudFormationParser().parse_text(
        """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Env:
    Type: String
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${Env}-bucket'
      Tags:
        - Key: Owner
          Value: !Ref Env
""",
        suffix=".yaml",
    )

    assert parsed.format_version == "2010-09-09"
    assert parsed.resources[0].properties["BucketName"] == {"Fn::Sub": "${Env}-bucket"}
    assert parsed.resources[0].properties["Tags"][0]["Value"] == {"Ref": "Env"}


def test_json_parsing_extracts_resources():
    parsed = CloudFormationParser().parse_text(
        '{"Resources":{"Role":{"Type":"AWS::IAM::Role","Properties":{}}}}',
        suffix=".json",
    )

    assert parsed.resources[0].logical_id == "Role"
    assert parsed.resources[0].resource_type == "AWS::IAM::Role"


def test_malformed_yaml_error():
    with pytest.raises(CloudFormationParseError):
        CloudFormationParser().parse_text("Resources: [", suffix=".yaml")


def test_empty_template():
    parsed = CloudFormationParser().parse_text("", suffix=".yaml")

    assert parsed.raw == {}
    assert parsed.resources == []
