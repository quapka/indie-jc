#!/usr/bin/env python3
"""
Analyze benchmark results from JavaCard operations.

Reads benchmark CSV files and generates statistical reports per operation
and per threshold-out-of-n configuration.
"""

import csv
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple
import statistics


def load_csv_data(filepath: Path) -> List[Dict]:
    """Load CSV file and return list of row dictionaries."""
    if not filepath.exists():
        print(f"Warning: {filepath} not found, skipping")
        return []

    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        return list(reader)


def analyze_per_card(data: List[Dict], config_key: str) -> Dict:
    """
    Analyze data per card for a specific configuration.

    Returns dict: {card_index: {operation: [durations]}}
    """
    card_data = defaultdict(lambda: defaultdict(list))

    for row in data:
        card_idx = int(row['card_index']) if row['card_index'] != '-1' else -1
        operation = row.get('operation', 'installation')  # Default for installation data
        duration = float(row['duration_ms'])

        card_data[card_idx][operation].append(duration)

    return card_data


def calculate_stats(values: List[float]) -> Dict:
    """Calculate min, max, mean, and std deviation."""
    if not values:
        return {'min': 0, 'max': 0, 'mean': 0, 'std': 0, 'count': 0}

    return {
        'min': min(values),
        'max': max(values),
        'mean': statistics.mean(values),
        'std': statistics.stdev(values) if len(values) > 1 else 0,
        'count': len(values)
    }


def print_stats(stats: Dict, indent: str = ""):
    """Print statistics in a formatted way."""
    print(f"{indent}Min:   {stats['min']:8.2f} ms")
    print(f"{indent}Max:   {stats['max']:8.2f} ms")
    print(f"{indent}Mean:  {stats['mean']:8.2f} ms")
    print(f"{indent}Std:   {stats['std']:8.2f} ms")
    print(f"{indent}Count: {stats['count']:8d} measurements")


def analyze_benchmark_file(filepath: Path, file_type: str):
    """Analyze a single benchmark CSV file."""
    print(f"\n{'='*70}")
    print(f"Analyzing: {filepath.name} ({file_type})")
    print(f"{'='*70}")

    data = load_csv_data(filepath)
    if not data:
        return

    # Group by threshold-out-of-nParties configuration
    configs = defaultdict(list)
    for row in data:
        config_key = f"{row['threshold']}-of-{row['nParties']}"
        configs[config_key].append(row)

    # Analyze each configuration
    for config_key in sorted(configs.keys()):
        config_data = configs[config_key]
        print(f"\n{'-'*70}")
        print(f"Configuration: {config_key}")
        print(f"{'-'*70}")

        # Get unique operations
        operations = set()
        for row in config_data:
            operations.add(row.get('operation', 'installation'))

        for operation in sorted(operations):
            print(f"\nOperation: {operation}")
            print(f"  {'─'*66}")

            # Filter data for this operation
            op_data = [row for row in config_data
                      if row.get('operation', 'installation') == operation]

            # Analyze per card
            card_data = analyze_per_card(op_data, config_key)

            # Per-card statistics
            all_values = []
            card_indices = sorted([idx for idx in card_data.keys() if idx != -1])

            if card_indices:
                print(f"\n  Per-card statistics:")
                for card_idx in card_indices:
                    if operation in card_data[card_idx]:
                        values = card_data[card_idx][operation]
                        all_values.extend(values)
                        stats = calculate_stats(values)

                        print(f"\n    Card {card_idx}:")
                        print_stats(stats, indent="      ")

            # Check for aggregate measurements (card_index = -1)
            if -1 in card_data and operation in card_data[-1]:
                print(f"\n  Aggregate measurement (total/parallel):")
                aggregate_values = card_data[-1][operation]
                aggregate_stats = calculate_stats(aggregate_values)
                print_stats(aggregate_stats, indent="    ")

            # Overall statistics across all cards
            if all_values:
                print(f"\n  Overall statistics (all cards combined):")
                overall_stats = calculate_stats(all_values)
                print_stats(overall_stats, indent="    ")


def generate_latex_table(filepath: Path, file_type: str):
    """Generate LaTeX table for the results."""
    data = load_csv_data(filepath)
    if not data:
        return

    # Group by configuration
    configs = defaultdict(list)
    for row in data:
        config_key = f"{row['threshold']}-of-{row['nParties']}"
        configs[config_key].append(row)

    print(f"\n{'='*70}")
    print(f"LaTeX Table for {filepath.name}")
    print(f"{'='*70}\n")

    # Generate a single table with all configurations
    print("% Seed Derivation Performance Table")
    print("% Requires \\usepackage{booktabs}, \\usepackage{multirow}, and \\usepackage[table]{xcolor}")
    print("\\begin{table}[h]")
    print("\\centering")
    print("\\small")
    print("\\setlength{\\tabcolsep}{8pt}")
    print("\\renewcommand{\\arraystretch}{1.1}")
    print("\\begin{tabular}{l c rrrr rrrr}")
    print("\\toprule")
    print("\\multirow{2}{*}{\\faUsersCog{}} & \\multirow{2}{*}{\\faUsersSecret{}} & \\multicolumn{4}{c}{Per-Card (ms)} & \\multicolumn{4}{c}{Total (ms)} \\\\")
    print("\\cmidrule(lr){3-6} \\cmidrule(lr){7-10}")
    print(" & & Min & Max & Avg & Std & Min & Max & Avg & Std \\\\")
    print("\\midrule")

    # Sort by number of parties first, then by threshold
    def config_sort_key(config_key):
        threshold, nParties = config_key.split('-of-')
        return (int(nParties), int(threshold))

    for config_key in sorted(configs.keys(), key=config_sort_key):
        config_data = configs[config_key]

        # Calculate number of compromised devices
        threshold, nParties = config_key.split('-of-')
        threshold, nParties = int(threshold), int(nParties)
        compromised = max(0, nParties - threshold - 1)

        # Get per-card statistics (seed_derivation)
        per_card_values = []
        for row in config_data:
            if (row.get('operation') == 'seed_derivation' and
                int(row['card_index']) != -1):
                per_card_values.append(float(row['duration_ms']))

        # Get total parallel statistics (seed_derivation_total)
        total_values = []
        for row in config_data:
            if (row.get('operation') == 'seed_derivation_total' and
                int(row['card_index']) == -1):
                total_values.append(float(row['duration_ms']))

        # Calculate statistics
        per_card_stats = calculate_stats(per_card_values)
        total_stats = calculate_stats(total_values)

        # Print table row
        if per_card_values or total_values:
            # Add gray background for specific configurations
            row_prefix = ""
            if config_key in ['2-of-4', '2-of-5', '3-of-5']:
                row_prefix = "\\rowcolor{gray!15} "

            print(f"{row_prefix}{config_key} & "
                  f"$\\leq$ {compromised} & "
                  f"{per_card_stats['min']:.0f} & "
                  f"{per_card_stats['max']:.0f} & "
                  f"{per_card_stats['mean']:.0f} & "
                  f"{per_card_stats['std']:.0f} & "
                  f"{total_stats['min']:.0f} & "
                  f"{total_stats['max']:.0f} & "
                  f"{total_stats['mean']:.0f} & "
                  f"{total_stats['std']:.0f} \\\\")

    print("\\bottomrule")
    print("\\end{tabular}")
    print("\\vspace{0.5em}")
    print("\\caption{Performance of the seed derivation per-card and in total for different threshold group configurations \\faUsersCog{}. "
          "The total includes the e2ee communication, partial seed shares verification and seed aggregation, but excludes authentication to identity provider and any network delays. "
          "The number of devices the attacker can compromise, while preserving the DKG security assumptions, is denoted \\faUserSecret{}.}")
    print("\\label{tab:seed_derivation_performance}")
    print("\\end{table}")


def generate_epoch_latex_table(filepath: Path):
    """Generate LaTeX table for Epoch results."""
    data = load_csv_data(filepath)
    if not data:
        return

    # Group by nParties (since we're using t-of-N format)
    configs = defaultdict(list)
    for row in data:
        nParties = row['nParties']
        configs[nParties].append(row)

    print(f"\n{'='*70}")
    print(f"LaTeX Table for {filepath.name} (Epoch)")
    print(f"{'='*70}\n")

    # Generate a table with partial signature stats (no verification)
    print("% MuSig2 Epoch Generation Performance Table")
    print("% Requires \\usepackage{booktabs}, \\usepackage{multirow}, and \\usepackage[table]{xcolor}")
    print("\\begin{table}[h]")
    print("\\centering")
    print("\\small")
    print("\\setlength{\\tabcolsep}{8pt}")
    print("\\renewcommand{\\arraystretch}{1.1}")
    print("\\begin{tabular}{c rrrr rrrr}")
    print("\\toprule")
    print("\\multirow{2}{*}{\\faUsersCog{}} & \\multicolumn{4}{c}{Per-Card (ms)} & \\multicolumn{4}{c}{Total (ms)} \\\\")
    print("\\cmidrule(lr){2-5} \\cmidrule(lr){6-9}")
    print(" & Min & Max & Avg & Std & Min & Max & Avg & Std \\\\")
    print("\\midrule")

    # Sort by number of parties
    for nParties in sorted(configs.keys(), key=int):
        config_data = configs[nParties]

        # Generic config label: t-of-N
        config_label = f"$t$-of-{nParties}"

        # Get per-card partial signature statistics
        per_card_values = []
        for row in config_data:
            if (row.get('operation') == 'musig2_partial_sig' and
                int(row['card_index']) != -1):
                per_card_values.append(float(row['duration_ms']))

        # Get total parallel statistics
        total_values = []
        for row in config_data:
            if (row.get('operation') == 'musig2_partial_sig_total' and
                int(row['card_index']) == -1):
                total_values.append(float(row['duration_ms']))

        # Calculate statistics
        per_card_stats = calculate_stats(per_card_values)
        total_stats = calculate_stats(total_values)

        # Print table row
        if per_card_values or total_values:
            # Add gray background for specific configurations
            row_prefix = ""
            if nParties in ['4', '5']:
                row_prefix = "\\rowcolor{gray!15} "

            print(f"{row_prefix}{config_label} & "
                  f"{per_card_stats['min']:.0f} & "
                  f"{per_card_stats['max']:.0f} & "
                  f"{per_card_stats['mean']:.0f} & "
                  f"{per_card_stats['std']:.0f} & "
                  f"{total_stats['min']:.0f} & "
                  f"{total_stats['max']:.0f} & "
                  f"{total_stats['mean']:.0f} & "
                  f"{total_stats['std']:.0f} \\\\")

    print("\\bottomrule")
    print("\\end{tabular}")
    print("\\vspace{0.5em}")
    print("\\caption{Performance of the epoch generation for different group sizes. "
          "Per-card shows individual card partial signature time, total shows parallel execution time "
          "including coordination overhead.}")
    print("\\label{tab:epoch_performance}")
    print("\\end{table}")


def main():
    """Main analysis function."""
    results_dir = Path("applet/benchmark_results")

    # Also check for results in current directory
    if not results_dir.exists():
        results_dir = Path("benchmark_results")

    if not results_dir.exists():
        print(f"Error: Benchmark results directory not found: {results_dir}")
        sys.exit(1)

    # Analyze installation results
    installation_file = results_dir / "installation_results.csv"
    if installation_file.exists():
        analyze_benchmark_file(installation_file, "Installation Benchmarks")

    # Analyze runtime benchmark results
    runtime_file = results_dir / "results.csv"
    if runtime_file.exists():
        analyze_benchmark_file(runtime_file, "Runtime Benchmarks")

    # Analyze MuSig2 results
    epoch_file = results_dir / "musig2_results.csv"
    if epoch_file.exists():
        analyze_benchmark_file(epoch_file, "MuSig2 Benchmarks")

    # Generate LaTeX tables
    print("\n\n")
    if installation_file.exists():
        generate_latex_table(installation_file, "Installation")

    if runtime_file.exists():
        generate_latex_table(runtime_file, "Runtime")

    if epoch_file.exists():
        generate_epoch_latex_table(epoch_file)


if __name__ == "__main__":
    main()
