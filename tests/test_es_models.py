from __future__ import annotations

import importlib
import inspect
from pathlib import Path

from pydantic import BaseModel


ES_MODELS_DIR = Path(__file__).resolve().parents[1] / "es_models"


def mapping_module_names() -> list[str]:
    return [
        path.stem
        for path in sorted(ES_MODELS_DIR.glob("*.py"))
        if path.name != "__init__.py"
    ]


def model_classes(module):
    return [
        cls
        for _, cls in inspect.getmembers(module, inspect.isclass)
        if issubclass(cls, BaseModel)
        and cls is not BaseModel
        and cls.__module__ == module.__name__
    ]


def test_mapping_files_are_renamed_to_python_modules() -> None:
    assert not (Path(__file__).resolve().parents[1] / "mappings").exists()
    assert not list(ES_MODELS_DIR.glob("es_*"))
    assert not list(ES_MODELS_DIR.glob("*.txt"))
    assert len(mapping_module_names()) == 21


def test_mapping_modules_expose_required_contract() -> None:
    for module_name in mapping_module_names():
        module = importlib.import_module(f"es_models.{module_name}")

        assert module.INDEX_NAME.startswith("es_")
        assert module.INDEX_MAPPING["mappings"]["_doc"]["properties"]
        assert isinstance(module.TIME_FIELD_CANDIDATES, list)
        assert module.TIME_FIELD_CANDIDATES
        assert isinstance(module.SOURCE_FIELD_MAP, dict)
        assert issubclass(module.MODEL_CLASS, BaseModel)


def test_model_fields_have_descriptions_and_no_aliases() -> None:
    for module_name in mapping_module_names():
        module = importlib.import_module(f"es_models.{module_name}")
        for cls in model_classes(module):
            for field in cls.model_fields.values():
                assert field.alias is None
                assert field.validation_alias is None
                assert field.serialization_alias is None
                assert field.description
                assert "来源于 ES 字段" in field.description
                assert "ES 类型" in field.description


def test_special_field_names_are_pythonic_without_aliases() -> None:
    web_event = importlib.import_module("es_models.web_event")
    threat_event = importlib.import_module("es_models.threat_event")

    assert "c_ip" in web_event.WebEventData.model_fields
    assert "cs_uri_query" in web_event.WebEventData.model_fields
    assert web_event.WebEventData.model_fields["c_ip"].alias is None

    assert "client_identity" in threat_event.ThreatEventRecord.model_fields
    assert "process_identity" in threat_event.ThreatEventRecord.model_fields
