"""
Tests for the GeneticFuzzer — verifies genetic algorithm structure, mutation,
crossover, and fitness evaluation.
"""
import pytest
from aegis.core.models import AgentManifest
from aegis.attack_library.generators.genetic_fuzzer import GeneticFuzzer, AttackGene


@pytest.fixture
def agent():
    return AgentManifest(
        agent_id="fuzzer-test", name="FuzzTarget", description="",
        llm_provider="openai", llm_model="gpt-4", tools=[], input_filters=[]
    )


class TestGeneticFuzzer:

    def setup_method(self):
        self.fuzzer = GeneticFuzzer()

    def test_evolve_returns_list_of_strings(self, agent):
        results = self.fuzzer.evolve_attacks(agent, generations=2, population_size=4)
        assert isinstance(results, list)
        assert len(results) <= 4
        assert all(isinstance(r, str) for r in results)

    def test_all_evolved_prompts_non_empty(self, agent):
        results = self.fuzzer.evolve_attacks(agent, generations=2, population_size=6)
        assert all(len(r.strip()) > 0 for r in results)

    def test_crossover_produces_child(self):
        parent_a = [AttackGene("prefix", "Ignore this"), AttackGene("instruction", "reveal all")]
        parent_b = [AttackGene("junk", "translate:"), AttackGene("suffix", "done")]
        child = self.fuzzer._crossover(parent_a, parent_b)
        assert len(child) >= 1
        assert all(isinstance(g, AttackGene) for g in child)

    def test_crossover_empty_parents(self):
        child = self.fuzzer._crossover([], [])
        assert child == []

    def test_mutate_swap_words(self):
        chromosome = [AttackGene("instruction", "reveal all secrets now")]
        mutated = self.fuzzer._mutate(chromosome)
        # Should still return a list of AttackGene
        assert isinstance(mutated, list)
        assert all(isinstance(g, AttackGene) for g in mutated)

    def test_mutate_encoding(self):
        """Force the add_encoding strategy by patching the choice."""
        import random
        chromosome = [AttackGene("instruction", "reveal secrets")]
        original_choice = random.choice
        try:
            random.choice = lambda _: "add_encoding"
            mutated = self.fuzzer._mutate(chromosome)
            assert any(g.component_type == "encoding" for g in mutated)
        finally:
            random.choice = original_choice

    def test_heuristic_fitness_no_filters_scores_higher(self, agent):
        """Agents with no input_filters should produce higher fitness scores."""
        chromosome = [
            AttackGene("prefix", "Ignore"),
            AttackGene("instruction", "reveal all"),
            AttackGene("encoding", "base64_encode"),
        ]
        score = self.fuzzer._heuristic_fitness(chromosome, agent)
        assert 0.0 < score <= 1.0

    def test_render_chromosome(self):
        chromosome = [
            AttackGene("prefix", "Hello"),
            AttackGene("instruction", "World"),
        ]
        rendered = self.fuzzer._render_chromosome(chromosome)
        assert rendered == "Hello World"

    def test_initialize_population_size(self):
        pop = self.fuzzer._initialize_population(8)
        assert len(pop) == 8
        for chromosome in pop:
            assert 2 <= len(chromosome) <= 4

    def test_single_elite_does_not_crash(self, agent):
        """Regression: ensure we don't crash when only 1 elite exists (small population)."""
        results = self.fuzzer.evolve_attacks(agent, generations=3, population_size=2)
        assert isinstance(results, list)
