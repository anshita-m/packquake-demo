import pytest

from graph_builder.cyclonedx_parser import SbomParseError, parse_sbom_document
from graph_builder.models import PackageKey, RequiresEdge


def _component(ecosystem, name, version):
    purl = f"pkg:{ecosystem}/{name}@{version}"
    return {"bom-ref": purl, "type": "library", "name": name, "version": version, "purl": purl}


def _doc(components, dependencies, root_ref="urn:app:test", app_name="test", app_version="1.0.0"):
    return {
        "metadata": {"component": {"bom-ref": root_ref, "type": "application", "name": app_name, "version": app_version}},
        "components": components,
        "dependencies": dependencies,
    }


def test_basic_direct_and_transitive_depth():
    a = _component("npm", "a", "1.0.0")
    b = _component("npm", "b", "1.0.0")
    c = _component("npm", "c", "1.0.0")
    doc = _doc(
        [a, b, c],
        [
            {"ref": "urn:app:test", "dependsOn": [a["bom-ref"], b["bom-ref"]]},
            {"ref": a["bom-ref"], "dependsOn": [c["bom-ref"]]},
        ],
    )

    parsed = parse_sbom_document(doc, app_id="test")

    by_pkg = {e.package.name: e for e in parsed.depends_on}
    assert by_pkg["a"].direct is True and by_pkg["a"].depth == 1
    assert by_pkg["b"].direct is True and by_pkg["b"].depth == 1
    assert by_pkg["c"].direct is False and by_pkg["c"].depth == 2

    assert parsed.requires == [
        RequiresEdge(source=PackageKey("a", "1.0.0", "npm"), target=PackageKey("c", "1.0.0", "npm"))
    ]


def test_duplicate_ref_in_dependencies_merges_dependson():
    a = _component("npm", "a", "1.0.0")
    b = _component("npm", "b", "1.0.0")
    c = _component("npm", "c", "1.0.0")
    doc = _doc(
        [a, b, c],
        [
            {"ref": "urn:app:test", "dependsOn": [a["bom-ref"]]},
            {"ref": "urn:app:test", "dependsOn": [b["bom-ref"]]},  # same ref, second entry
            {"ref": a["bom-ref"], "dependsOn": [c["bom-ref"]]},
        ],
    )

    parsed = parse_sbom_document(doc, app_id="test")
    names = {e.package.name for e in parsed.depends_on}
    assert names == {"a", "b", "c"}


def test_missing_dependencies_array_falls_back_to_direct_depth_1(caplog):
    a = _component("npm", "a", "1.0.0")
    b = _component("npm", "b", "1.0.0")
    doc = {
        "metadata": {"component": {"bom-ref": "urn:app:test", "type": "application", "name": "test", "version": "1.0.0"}},
        "components": [a, b],
        # no "dependencies" key at all
    }

    with caplog.at_level("WARNING"):
        parsed = parse_sbom_document(doc, app_id="test")

    assert {e.package.name for e in parsed.depends_on} == {"a", "b"}
    assert all(e.direct and e.depth == 1 for e in parsed.depends_on)
    assert any("no 'dependencies' array" in msg for msg in caplog.messages)


def test_empty_dependencies_array_means_zero_edges():
    a = _component("npm", "a", "1.0.0")
    doc = _doc([a], [])  # explicitly declared empty, not missing

    parsed = parse_sbom_document(doc, app_id="test")
    assert parsed.depends_on == []


def test_nonempty_dependencies_array_but_root_never_linked_falls_back(caplog):
    # Observed in real Syft directory scans of npm projects: a full,
    # non-empty component-to-component dependency graph is present, but the
    # root's own bom-ref is never used as a `ref` anywhere in it.
    a = _component("npm", "a", "1.0.0")
    b = _component("npm", "b", "1.0.0")
    doc = _doc(
        [a, b],
        [{"ref": a["bom-ref"], "dependsOn": [b["bom-ref"]]}],  # a->b present, but root->* absent
    )

    with caplog.at_level("WARNING"):
        parsed = parse_sbom_document(doc, app_id="test")

    # Root linkage falls back to "everything is direct depth-1"...
    assert {e.package.name for e in parsed.depends_on} == {"a", "b"}
    assert all(e.direct and e.depth == 1 for e in parsed.depends_on)
    # ...but the real a->b REQUIRES edge captured in the array is untouched.
    assert len(parsed.requires) == 1
    assert parsed.requires[0].source.name == "a"
    assert parsed.requires[0].target.name == "b"
    assert any("never listed as a dependent" in msg for msg in caplog.messages)


def test_shortest_path_depth_wins_on_diamond():
    # root -> a -> c (depth 2 via a)
    # root -> c directly as well (depth 1 via direct edge)
    a = _component("npm", "a", "1.0.0")
    c = _component("npm", "c", "1.0.0")
    doc = _doc(
        [a, c],
        [
            {"ref": "urn:app:test", "dependsOn": [a["bom-ref"], c["bom-ref"]]},
            {"ref": a["bom-ref"], "dependsOn": [c["bom-ref"]]},
        ],
    )

    parsed = parse_sbom_document(doc, app_id="test")
    by_pkg = {e.package.name: e for e in parsed.depends_on}
    assert by_pkg["c"].depth == 1
    assert by_pkg["c"].direct is True


def test_dangling_dependency_ref_is_skipped_not_fatal(caplog):
    a = _component("npm", "a", "1.0.0")
    doc = _doc(
        [a],
        [{"ref": "urn:app:test", "dependsOn": [a["bom-ref"], "pkg:npm/ghost@1.0.0"]}],
    )

    with caplog.at_level("WARNING"):
        parsed = parse_sbom_document(doc, app_id="test")

    assert {e.package.name for e in parsed.depends_on} == {"a"}
    assert any("no matching component" in msg for msg in caplog.messages)


def test_missing_root_component_raises():
    doc = {"components": [], "dependencies": []}
    with pytest.raises(SbomParseError):
        parse_sbom_document(doc, app_id="test")


def test_component_without_purl_falls_back_to_type_as_ecosystem():
    comp = {"bom-ref": "ref-x", "type": "library", "name": "mystery-pkg", "version": "9.9.9"}
    doc = _doc([comp], [{"ref": "urn:app:test", "dependsOn": ["ref-x"]}])

    parsed = parse_sbom_document(doc, app_id="test")
    assert parsed.depends_on[0].package == PackageKey("mystery-pkg", "9.9.9", "library")


def test_ecosystem_derived_from_purl_type_not_component_type():
    comp = _component("pypi", "requests", "2.31.0")
    comp["type"] = "library"  # CycloneDX component type, unrelated to purl ecosystem
    doc = _doc([comp], [{"ref": "urn:app:test", "dependsOn": [comp["bom-ref"]]}])

    parsed = parse_sbom_document(doc, app_id="test")
    assert parsed.depends_on[0].package.ecosystem == "pypi"


def test_app_id_stamped_onto_every_depends_on_edge():
    a = _component("npm", "a", "1.0.0")
    doc = _doc([a], [{"ref": "urn:app:test", "dependsOn": [a["bom-ref"]]}])

    parsed = parse_sbom_document(doc, app_id="my-app")
    assert parsed.app_id == "my-app"
    assert all(e.app_id == "my-app" for e in parsed.depends_on)
