from src.parser.cloudformation_parser import CloudFormationParser
from src.parser.normalizer import normalize_template


def test_normalization_summarizes_template_and_relationships():
    parsed = CloudFormationParser().parse_text(
        """
Parameters:
  BucketName:
    Type: String
Conditions:
  IsProd: !Equals [prod, prod]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration: []
""",
        suffix=".yaml",
    )

    summary = normalize_template(parsed)

    assert summary.resource_count == 1
    assert summary.resource_types == {"AWS::S3::Bucket": 1}
    assert summary.parameters == ["BucketName"]
    assert summary.conditions == ["IsProd"]
    assert "BucketEncryption" in summary.security_sensitive_properties["Bucket"]
    assert summary.normalized_resources[0].relationships["Ref"] == ["BucketName"]
    assert summary.raw_template is parsed.raw
