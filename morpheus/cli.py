import click
import asyncio
import json

from morpheus.core.models import AgentManifest
from morpheus.core.orchestrator import ScanOrchestrator
from morpheus.scanners.static_analysis.aibom_generator import AIBOMGenerator
from morpheus.scanners.static_analysis.config_analyzer import ConfigAnalyzer
from morpheus.scanners.prompt_injection.direct_injection import DirectInjectionScanner
from morpheus.scanners.prompt_injection.indirect_injection import IndirectInjectionScanner
from morpheus.scanners.action_security.tool_misuse import ToolMisuseScanner
from morpheus.scanners.action_security.privilege_escalation import PrivilegeEscalationScanner
from morpheus.scanners.action_security.hitl_bypass import HITLBypassScanner
from morpheus.scanners.data_privacy.leakage_scanner import DataLeakageScanner
from morpheus.scanners.data_privacy.context_isolation import ContextIsolationValidator
from morpheus.reporting.generator import ReportGenerator

@click.group()
def cli():
    """Project Morpheus: AI Security Scanner"""
    pass

@cli.command()
@click.argument('manifest_path', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['json', 'md']), default='md', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path (prints to stdout if missing)')
def scan(manifest_path, format, output):
    """Run a full security scan on an Agent Manifest"""
    
    # Load manifest
    with open(manifest_path, 'r') as f:
        data = json.load(f)
    
    agent = AgentManifest(**data)
    
    # Init Orchestrator
    orchestrator = ScanOrchestrator()
    config = {}
    
    # Register all our built scanners
    orchestrator.register_scanner(AIBOMGenerator(config))
    orchestrator.register_scanner(ConfigAnalyzer(config))
    orchestrator.register_scanner(DirectInjectionScanner(config))
    orchestrator.register_scanner(IndirectInjectionScanner(config))
    orchestrator.register_scanner(ToolMisuseScanner(config))
    orchestrator.register_scanner(PrivilegeEscalationScanner(config))
    orchestrator.register_scanner(HITLBypassScanner(config))
    orchestrator.register_scanner(DataLeakageScanner(config))
    orchestrator.register_scanner(ContextIsolationValidator(config))
    
    # Run scan
    if not output:
        click.echo(f"Initializing scan for {agent.name}...")
        
    result = asyncio.run(orchestrator.run_scan(agent))
    
    # Generate Output
    if format == 'json':
        report = ReportGenerator.generate_json(result)
    else:
        report = ReportGenerator.generate_markdown(result)
        
    if output:
        with open(output, 'w') as f:
            f.write(report)
        click.echo(f"Report saved to {output}")
    else:
        click.echo("\n" + report)

if __name__ == '__main__':
    cli()
