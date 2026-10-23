#!/usr/bin/env python3
"""Materialize one clean control and three isolated source mutations (researcher only)."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class Clean(ast.NodeTransformer):
    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and node.value.id == 'self' and node.attr == 'bug':
            return ast.copy_location(ast.Constant('none'), node)
        return self.generic_visit(node)

    def visit_Assign(self, node):
        if any(isinstance(t, ast.Attribute) and t.attr == 'bug' for t in node.targets):
            return None
        return self.generic_visit(node)

    def visit_Compare(self, node):
        node = self.generic_visit(node)
        if len(node.ops) != 1:
            return node
        try:
            left, right = ast.literal_eval(node.left), ast.literal_eval(node.comparators[0])
        except (ValueError, TypeError):
            return node
        op = node.ops[0]
        if isinstance(op, ast.Eq):
            return ast.Constant(left == right)
        if isinstance(op, ast.NotEq):
            return ast.Constant(left != right)
        if isinstance(op, ast.NotIn):
            return ast.Constant(left not in right)
        return node

    def visit_BoolOp(self, node):
        node = self.generic_visit(node)
        if isinstance(node.op, ast.And):
            if any(isinstance(v, ast.Constant) and v.value is False for v in node.values):
                return ast.Constant(False)
        return node

    def visit_UnaryOp(self, node):
        node = self.generic_visit(node)
        if isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Constant):
            return ast.Constant(not node.operand.value)
        return node

    def visit_If(self, node):
        node = self.generic_visit(node)
        if isinstance(node.test, ast.Constant):
            return node.body if node.test.value else node.orelse
        return node


class Mutate(ast.NodeTransformer):
    def __init__(self, bug):
        self.bug, self.changes = bug, 0

    def visit_Assign(self, node):
        text = ast.unparse(node)
        if self.bug == 'wrong_port' and text == 'output = table.get(eth.dst, o.OFPP_FLOOD)':
            self.changes += 1
            return [node, ast.parse('if output < o.OFPP_MAX:\n    output = 3 if output != 3 else 2').body[0]]
        if self.bug == 'stale_mapping' and text == 'table[eth.src] = incoming':
            self.changes += 1
            return ast.If(test=ast.parse('eth.src not in table', mode='eval').body, body=[node], orelse=[])
        return self.generic_visit(node)

    def visit_For(self, node):
        if self.bug == 'cached_bypass' and ast.unparse(node.iter) == 'new - self.blocked':
            self.changes += 1
            return None
        return self.generic_visit(node)


def materialize(destination):
    # This tool targets this explicit template only, never arbitrary GitHub source.
    source = (ROOT / 'control_template.py').read_text()
    clean = ast.fix_missing_locations(Clean().visit(ast.parse(source)))
    baseline = ast.unparse(clean) + '\n'
    if 'self.bug' in baseline or 'RAIN_BUG' in baseline:
        raise ValueError('Unremoved mutation switches')
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {'template_sha256': hashlib.sha256(source.encode()).hexdigest(), 'variants': {}}
    for bug in ['good', 'wrong_port', 'stale_mapping', 'cached_bypass']:
        tree = ast.parse(baseline)
        if bug != 'good':
            transformer = Mutate(bug)
            tree = transformer.visit(tree)
            if transformer.changes != 1:
                raise ValueError('Expected exactly one mutation for ' + bug)
        text = ast.unparse(ast.fix_missing_locations(tree)) + '\n'
        compile(text, bug + '.py', 'exec')
        (destination / (bug + '.py')).write_text(text)
        manifest['variants'][bug] = hashlib.sha256(text.encode()).hexdigest()
        if bug != 'good':
            (destination / (bug + '.patch')).write_text(''.join(difflib.unified_diff(
                baseline.splitlines(True), text.splitlines(True), fromfile='good.py', tofile=bug + '.py')))
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'variants')
    args = parser.parse_args()
    materialize(args.output.resolve())
    print('Created independent source files in', args.output)
