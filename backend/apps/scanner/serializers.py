from rest_framework import serializers

from .models import Finding, Scan
from .services.url_validator import validate_git_url, validate_web_url


class ScanCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ["id", "source_type", "source_url", "source_file"]

    def validate_source_url(self, value):
        if value:
            source_type = self.initial_data.get("source_type", "")
            if source_type in ("dast", "pwn"):
                validate_web_url(value)
            else:
                validate_git_url(value)
        return value

    def validate_source_file(self, value):
        if value and value.size > 50 * 1024 * 1024:
            raise serializers.ValidationError("File exceeds 50 MB limit.")
        return value

    def validate(self, data):
        source_type = data.get("source_type")
        source_url = data.get("source_url", "")
        source_file = data.get("source_file")

        if source_type == "git" and not source_url:
            raise serializers.ValidationError(
                {"source_url": "A Git URL is required for source_type 'git'."}
            )

        if source_type == "dast" and not source_url:
            raise serializers.ValidationError(
                {"source_url": "A URL is required for DAST scans."}
            )

        if source_type == "pwn" and not source_url:
            raise serializers.ValidationError(
                {"source_url": "A URL is required for PWN scans."}
            )

        if source_type in ("zip", "files") and not source_file:
            raise serializers.ValidationError(
                {"source_file": "A file upload is required for source_type 'zip' or 'files'."}
            )

        return data


class ScanStatusSerializer(serializers.ModelSerializer):
    source_filename = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            "id",
            "source_type",
            "source_url",
            "source_filename",
            "status",
            "detected_languages",
            "error_message",
            "created_at",
            "completed_at",
            "total_findings",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "security_score",
            "cvss_max_score",
            "progress",
        ]
        read_only_fields = fields

    def get_source_filename(self, obj) -> str:
        if obj.source_file:
            name = obj.source_file.name.split("/")[-1]
            # Strip common extensions
            for ext in (".zip", ".tar.gz", ".tar", ".gz"):
                if name.lower().endswith(ext):
                    name = name[: -len(ext)]
                    break
            return name
        # For DAST scans, workspace_path stores the site <title>
        if obj.source_type == "dast" and obj.workspace_path:
            return obj.workspace_path
        return ""


class FindingSerializer(serializers.ModelSerializer):
    has_fix = serializers.SerializerMethodField()
    owasp_recommendation = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = [
            "id", "tool", "rule_id", "file_path", "line_start", "line_end",
            "code_snippet", "severity", "owasp_category", "owasp_confidence", "title", "description",
            "has_fix", "fixed_code", "fix_explanation", "fix_pr_url", "status",
            "owasp_recommendation",
        ]
        read_only_fields = fields

    def get_has_fix(self, obj) -> bool:
        return bool(obj.fix_generated_at)

    def get_owasp_recommendation(self, obj) -> str:
        from .services.owasp_mapper import get_owasp_recommendation  # noqa: PLC0415

        return get_owasp_recommendation(obj.owasp_category)


class FindingUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = ["status"]
