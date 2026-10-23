#!/usr/bin/env python3
"""Materialize one clean control and three isolated source mutations (researcher only)."""
import argparse
import ast
import difflib
import hashlib
import json
from pathlib import Path

VALIDATION_DIRECTORY = Path(__file__).resolve().parent


class FaultSelectionRemover(ast.NodeTransformer):
    """Remove runtime fault selection to produce the intended reference controller."""

    def visit_Attribute(self, syntax_node):
        """Replace a reference to the template fault selector with the no-fault value."""
        if (
            isinstance(syntax_node.value, ast.Name)
            and syntax_node.value.id == "self"
            and syntax_node.attr == "injected_fault"
        ):
            return ast.copy_location(ast.Constant("none"), syntax_node)
        return self.generic_visit(syntax_node)

    def visit_Assign(self, syntax_node):
        """Remove the fault selector assignment from the reference template."""
        if any(
            isinstance(assignment_target, ast.Attribute)
            and assignment_target.attr == "injected_fault"
            for assignment_target in syntax_node.targets
        ):
            return None
        return self.generic_visit(syntax_node)

    def visit_Compare(self, syntax_node):
        """Evaluate comparisons whose operands are literal values."""
        syntax_node = self.generic_visit(syntax_node)
        if len(syntax_node.ops) != 1:
            return syntax_node
        try:
            left_operand, right_operand = ast.literal_eval(
                syntax_node.left
            ), ast.literal_eval(syntax_node.comparators[0])
        except (ValueError, TypeError):
            return syntax_node
        comparison_operator = syntax_node.ops[0]
        if isinstance(comparison_operator, ast.Eq):
            return ast.Constant(left_operand == right_operand)
        if isinstance(comparison_operator, ast.NotEq):
            return ast.Constant(left_operand != right_operand)
        if isinstance(comparison_operator, ast.NotIn):
            return ast.Constant(left_operand not in right_operand)
        return syntax_node

    def visit_BoolOp(self, syntax_node):
        """Simplify an AND condition containing a literal false operand."""
        syntax_node = self.generic_visit(syntax_node)
        if isinstance(syntax_node.op, ast.And):
            if any(
                isinstance(operand, ast.Constant) and operand.value is False
                for operand in syntax_node.values
            ):
                return ast.Constant(False)
        return syntax_node

    def visit_UnaryOp(self, syntax_node):
        """Simplify a NOT condition with a literal operand."""
        syntax_node = self.generic_visit(syntax_node)
        if isinstance(syntax_node.op, ast.Not) and isinstance(
            syntax_node.operand, ast.Constant
        ):
            return ast.Constant(not syntax_node.operand.value)
        return syntax_node

    def visit_If(self, syntax_node):
        """Keep only the selected branch of an already evaluated condition."""
        syntax_node = self.generic_visit(syntax_node)
        if isinstance(syntax_node.test, ast.Constant):
            return syntax_node.body if syntax_node.test.value else syntax_node.orelse
        return syntax_node


class ControllerFaultInjector(ast.NodeTransformer):
    """Apply one named defect to a reference controller syntax tree."""

    def __init__(self, fault_name):
        self.fault_name, self.mutation_count = fault_name, 0

    def visit_Assign(self, syntax_node):
        """Inject wrong-output or stale-location behavior at its assignment."""
        controller_source_code = ast.unparse(syntax_node)
        if (
            self.fault_name == "wrong_output_port"
            and controller_source_code
            == "egress_port = host_locations.get(ethernet_header.dst, ofproto.OFPP_FLOOD)"
        ):
            self.mutation_count += 1
            return [
                syntax_node,
                ast.parse(
                    "if egress_port < ofproto.OFPP_MAX:\n    egress_port = 3 if egress_port != 3 else 2"
                ).body[0],
            ]
        if (
            self.fault_name == "stale_host_location"
            and controller_source_code
            == "host_locations[ethernet_header.src] = ingress_port"
        ):
            self.mutation_count += 1
            return ast.If(
                test=ast.parse(
                    "ethernet_header.src not in host_locations", mode="eval"
                ).body,
                body=[syntax_node],
                orelse=[],
            )
        return self.generic_visit(syntax_node)

    def visit_For(self, syntax_node):
        """Remove the new-policy drop installation loop for cached-policy bypass."""
        if (
            self.fault_name == "cached_policy_bypass"
            and ast.unparse(syntax_node.iter)
            == "updated_blocklist - self.blocked_destination_macs"
        ):
            self.mutation_count += 1
            return None
        return self.generic_visit(syntax_node)


def generate_controller_variants(output_directory):
    # This tool targets this explicit template only, never arbitrary GitHub source.
    """Write the reference, one-defect controllers, source diffs, and hash manifest."""
    template_source_code = (VALIDATION_DIRECTORY / "controller_template.py").read_text()
    reference_syntax_tree = ast.fix_missing_locations(
        FaultSelectionRemover().visit(ast.parse(template_source_code))
    )
    reference_source_code = ast.unparse(reference_syntax_tree) + "\n"
    if (
        "self.injected_fault" in reference_source_code
        or "RAIN_BUG" in reference_source_code
    ):
        raise ValueError("Unremoved mutation switches")
    output_directory.mkdir(parents=True, exist_ok=False)
    source_manifest = {
        "template_sha256": hashlib.sha256(template_source_code.encode()).hexdigest(),
        "variants": {},
    }
    for fault_name in [
        "reference_controller",
        "wrong_output_port",
        "stale_host_location",
        "cached_policy_bypass",
    ]:
        variant_syntax_tree = ast.parse(reference_source_code)
        if fault_name != "reference_controller":
            fault_transformer = ControllerFaultInjector(fault_name)
            variant_syntax_tree = fault_transformer.visit(variant_syntax_tree)
            if fault_transformer.mutation_count != 1:
                raise ValueError("Expected exactly one mutation for " + fault_name)
        controller_source_code = (
            ast.unparse(ast.fix_missing_locations(variant_syntax_tree)) + "\n"
        )
        compile(controller_source_code, fault_name + ".py", "exec")
        (output_directory / (fault_name + ".py")).write_text(controller_source_code)
        source_manifest["variants"][fault_name] = hashlib.sha256(
            controller_source_code.encode()
        ).hexdigest()
        if fault_name != "reference_controller":
            (output_directory / (fault_name + ".patch")).write_text(
                "".join(
                    difflib.unified_diff(
                        reference_source_code.splitlines(True),
                        controller_source_code.splitlines(True),
                        fromfile="reference_controller.py",
                        tofile=fault_name + ".py",
                    )
                )
            )
    (output_directory / "source_manifest.json").write_text(
        json.dumps(source_manifest, indent=2) + "\n"
    )
    return source_manifest


def main():
    """Read the destination directory and generate a fresh set of controller files."""
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "--output-directory",
        "--output",
        dest="output_directory",
        type=Path,
        default=VALIDATION_DIRECTORY / "controller_variants",
    )
    options = argument_parser.parse_args()
    generate_controller_variants(options.output_directory.resolve())
    print("Created independent source files in", options.output_directory)


if __name__ == "__main__":
    main()
