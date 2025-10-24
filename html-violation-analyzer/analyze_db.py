"""
Enhanced SQLite Data Analysis Script for HTML Violations
Focuses on violation trends over time with comprehensive analysis
"""

import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import sys
import os
from datetime import datetime
from scipy import stats

plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

def extract_violation_data(conn):
    """Extract violation data with proper joins"""
    
    print("\n=== EXTRACTING VIOLATION DATA ===")
    
    # First, check the exact table structure
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [table[0] for table in cursor.fetchall()]
    print(f"Available tables: {tables}")
    
    # Main query to get violation data
    query = """
    SELECT 
        w.country,
        w.hostname,
        w.domain,
        w.timestamp,
        w.size,
        r.name as rule_code,
        r.name_informal as rule_name,
        r.description as rule_description,
        cr.result,
        w.path
    FROM website w
    JOIN checker_results cr ON w.id = cr.website_id
    JOIN checker_rule r ON cr.rule_id = r.id
    WHERE w.country IS NOT NULL
    ORDER BY w.timestamp, w.country, r.name
    """
    
    try:
        df = pd.read_sql_query(query, conn)
        print(f"Extracted {len(df)} violation checks")
        
        # Convert result to violation (0 = violation, 1 = pass)
        df['is_violation'] = (df['result'] == 0).astype(int)
        
        # Parse timestamps
        df = parse_timestamps(df)
        
        # Extract year from filename if timestamp parsing fails
        if 'year' not in df.columns or df['year'].isna().all():
            df['year'] = df['path'].apply(extract_year_from_path)
        
        return df
        
    except Exception as e:
        print(f"Error extracting data: {e}")
        return None

def extract_year_from_path(path):
    """Extract year from file path like '2022_index_www_president_gov_ua_20220404234046.html'"""
    try:
        filename = os.path.basename(path)
        if filename.startswith('20'):
            return int(filename[:4])
        parts = filename.split('_')
        for part in parts:
            if part.startswith('20') and len(part) >= 4:
                return int(part[:4])
    except:
        pass
    return np.nan

def parse_timestamps(df):
    """Parse timestamps and extract years"""
    
    print("\n=== PARSING TIMESTAMPS ===")
    
    # Try multiple parsing strategies
    if df['timestamp'].dtype == 'object':
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        except:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed')
            except:
                print("Could not parse timestamps as datetime")
    
    # Extract year
    if pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['year'] = df['timestamp'].dt.year
    else:
        # Try to extract year from path
        df['year'] = df['path'].apply(extract_year_from_path)
    
    # Filter reasonable years
    df = df[df['year'].between(2000, 2030)]
    
    print(f"Years found: {sorted(df['year'].dropna().unique())}")
    
    return df

def create_violation_trends_by_country(df):
    """Create violation trend plots for each country"""
    
    print("\n=== CREATING VIOLATION TREND PLOTS ===")
    
    if not os.path.exists('plots'):
        os.makedirs('plots')
    
    # Calculate violation rates by country, year, and rule
    violation_stats = df.groupby(['country', 'year', 'rule_code', 'rule_name']).agg({
        'is_violation': ['sum', 'count', 'mean']
    }).reset_index()
    
    violation_stats.columns = ['country', 'year', 'rule_code', 'rule_name', 
                              'violations', 'total_checks', 'violation_rate']
    
    # Get unique countries
    countries = sorted(df['country'].unique())
    
    # Create individual country trend plots
    for country in countries:
        create_country_violation_trends(df, violation_stats, country)
    
    # Create combined overview
    create_violation_overview(violation_stats)
    
    return violation_stats

def create_country_violation_trends(df, violation_stats, country):
    """Create detailed violation trend plot for a specific country"""
    
    country_data = violation_stats[violation_stats['country'] == country]
    
    if len(country_data) == 0:
        return
    
    # Create figure with subplots
    fig = plt.figure(figsize=(20, 12))
    
    # Main plot: Violation rates by rule over time
    ax1 = plt.subplot(2, 2, 1)
    
    rules = country_data['rule_code'].unique()
    colors = plt.cm.tab20(np.linspace(0, 1, len(rules)))
    
    for i, rule in enumerate(rules):
        rule_data = country_data[country_data['rule_code'] == rule]
        rule_data = rule_data.sort_values('year')
        
        ax1.plot(rule_data['year'], rule_data['violation_rate'] * 100, 
                marker='o', linewidth=2.5, markersize=8,
                label=f"{rule} ({rule_data['rule_name'].iloc[0][:30]}...)" 
                if len(rule_data['rule_name'].iloc[0]) > 30 
                else f"{rule} ({rule_data['rule_name'].iloc[0]})",
                color=colors[i])
    
    ax1.set_title(f'Violation Rates Over Time - {country}', fontsize=16, fontweight='bold')
    ax1.set_xlabel('Year', fontsize=12)
    ax1.set_ylabel('Violation Rate (%)', fontsize=12)
    ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=10)
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim(0, 105)
    
    # Subplot 2: Total violations by year
    ax2 = plt.subplot(2, 2, 2)
    
    yearly_totals = country_data.groupby('year').agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    
    x = yearly_totals['year']
    y1 = yearly_totals['violations']
    y2 = yearly_totals['total_checks'] - yearly_totals['violations']
    
    ax2.bar(x, y1, label='Violations', color='#FF6B6B', alpha=0.8)
    ax2.bar(x, y2, bottom=y1, label='Passed', color='#4ECDC4', alpha=0.8)
    
    ax2.set_title(f'Total Checks and Violations by Year - {country}', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Number of Checks')
    ax2.legend()
    ax2.grid(True, alpha=0.3, axis='y')
    
    # Subplot 3: Heatmap of violations by rule and year
    ax3 = plt.subplot(2, 2, 3)
    
    heatmap_data = country_data.pivot_table(
        index='rule_code', 
        columns='year', 
        values='violation_rate',
        fill_value=0
    )
    
    sns.heatmap(heatmap_data * 100, annot=True, fmt='.1f', cmap='YlOrRd', 
                cbar_kws={'label': 'Violation Rate (%)'}, ax=ax3)
    ax3.set_title(f'Violation Rate Heatmap - {country}', fontsize=14, fontweight='bold')
    ax3.set_xlabel('Year')
    ax3.set_ylabel('Rule Code')
    
    # Subplot 4: Top violating domains
    ax4 = plt.subplot(2, 2, 4)
    
    country_df = df[df['country'] == country]
    domain_violations = country_df.groupby('domain')['is_violation'].agg(['sum', 'count'])
    domain_violations['rate'] = domain_violations['sum'] / domain_violations['count']
    domain_violations = domain_violations.sort_values('sum', ascending=False).head(10)
    
    y_pos = np.arange(len(domain_violations))
    ax4.barh(y_pos, domain_violations['sum'], color='coral')
    ax4.set_yticks(y_pos)
    ax4.set_yticklabels(domain_violations.index, fontsize=10)
    ax4.set_xlabel('Total Violations')
    ax4.set_title(f'Top 10 Violating Domains - {country}', fontsize=14, fontweight='bold')
    ax4.grid(True, alpha=0.3, axis='x')
    
    plt.suptitle(f'Comprehensive Violation Analysis for {country}', fontsize=18, fontweight='bold')
    plt.tight_layout()
    plt.savefig(f'plots/violation_trends_{country}.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Created violation_trends_{country}.png")

def create_violation_overview(violation_stats):
    """Create overview plots comparing all countries"""
    
    fig = plt.figure(figsize=(20, 15))
    
    # Plot 1: Overall violation trends by country
    ax1 = plt.subplot(3, 2, 1)
    
    country_yearly = violation_stats.groupby(['country', 'year']).agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    country_yearly['violation_rate'] = country_yearly['violations'] / country_yearly['total_checks'] * 100
    
    for country in country_yearly['country'].unique():
        country_data = country_yearly[country_yearly['country'] == country].sort_values('year')
        ax1.plot(country_data['year'], country_data['violation_rate'], 
                marker='o', linewidth=2.5, markersize=8, label=country)
    
    ax1.set_title('Overall Violation Rates by Country Over Time', fontsize=16, fontweight='bold')
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Violation Rate (%)')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Rule performance across all countries
    ax2 = plt.subplot(3, 2, 2)
    
    rule_stats = violation_stats.groupby('rule_code').agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    rule_stats['violation_rate'] = rule_stats['violations'] / rule_stats['total_checks'] * 100
    rule_stats = rule_stats.sort_values('violation_rate', ascending=False)
    
    bars = ax2.bar(range(len(rule_stats)), rule_stats['violation_rate'], 
                    color=plt.cm.Reds(rule_stats['violation_rate'] / 100))
    ax2.set_xticks(range(len(rule_stats)))
    ax2.set_xticklabels(rule_stats['rule_code'], rotation=45)
    ax2.set_title('Violation Rates by Rule (All Countries)', fontsize=16, fontweight='bold')
    ax2.set_ylabel('Violation Rate (%)')
    ax2.grid(True, alpha=0.3, axis='y')
    
    # Add value labels on bars
    for bar, rate in zip(bars, rule_stats['violation_rate']):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{rate:.1f}%', ha='center', va='bottom', fontsize=10)
    
    # Plot 3: Country comparison heatmap
    ax3 = plt.subplot(3, 2, 3)
    
    country_rule_pivot = violation_stats.groupby(['country', 'rule_code']).agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    country_rule_pivot['violation_rate'] = country_rule_pivot['violations'] / country_rule_pivot['total_checks'] * 100
    
    heatmap_data = country_rule_pivot.pivot(index='country', columns='rule_code', values='violation_rate')
    
    sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='YlOrRd', 
                cbar_kws={'label': 'Violation Rate (%)'}, ax=ax3)
    ax3.set_title('Violation Rate Heatmap by Country and Rule', fontsize=14, fontweight='bold')
    
    # Plot 4: Trend analysis - improvement vs deterioration
    ax4 = plt.subplot(3, 2, 4)
    
    trend_analysis = []
    for country in violation_stats['country'].unique():
        for rule in violation_stats['rule_code'].unique():
            rule_country_data = violation_stats[
                (violation_stats['country'] == country) & 
                (violation_stats['rule_code'] == rule)
            ].sort_values('year')
            
            if len(rule_country_data) >= 2:
                years = rule_country_data['year'].values
                rates = rule_country_data['violation_rate'].values
                
                if len(years) >= 2:
                    # Calculate trend
                    slope, _, _, _, _ = stats.linregress(years, rates)
                    trend_analysis.append({
                        'country': country,
                        'rule': rule,
                        'trend': slope * 100,  # Convert to percentage points per year
                        'start_rate': rates[0] * 100,
                        'end_rate': rates[-1] * 100,
                        'years_covered': len(years)
                    })
    
    trend_df = pd.DataFrame(trend_analysis)
    
    # Plot improvement vs deterioration
    improving = trend_df[trend_df['trend'] < -1]  # More than 1% improvement per year
    deteriorating = trend_df[trend_df['trend'] > 1]  # More than 1% deterioration per year
    
    ax4.barh(['Improving', 'Stable', 'Deteriorating'], 
             [len(improving), len(trend_df) - len(improving) - len(deteriorating), len(deteriorating)],
             color=['#4ECDC4', '#FFA07A', '#FF6B6B'])
    ax4.set_title('Rule Compliance Trends Across Countries', fontsize=14, fontweight='bold')
    ax4.set_xlabel('Number of Country-Rule Combinations')
    
    # Plot 5: Year-over-year changes
    ax5 = plt.subplot(3, 2, 5)
    
    # Calculate year-over-year changes for each country
    yoy_changes = []
    for country in country_yearly['country'].unique():
        country_data = country_yearly[country_yearly['country'] == country].sort_values('year')
        if len(country_data) > 1:
            for i in range(1, len(country_data)):
                yoy_changes.append({
                    'country': country,
                    'year': f"{country_data.iloc[i-1]['year']}-{country_data.iloc[i]['year']}",
                    'change': country_data.iloc[i]['violation_rate'] - country_data.iloc[i-1]['violation_rate']
                })
    
    yoy_df = pd.DataFrame(yoy_changes)
    if not yoy_df.empty:
        yoy_pivot = yoy_df.pivot(index='country', columns='year', values='change')
        
        sns.heatmap(yoy_pivot, annot=True, fmt='.1f', cmap='RdYlGn_r', center=0,
                    cbar_kws={'label': 'YoY Change in Violation Rate (%)'}, ax=ax5)
        ax5.set_title('Year-over-Year Changes in Violation Rates', fontsize=14, fontweight='bold')
    
    # Plot 6: Statistical summary
    ax6 = plt.subplot(3, 2, 6)
    ax6.axis('off')
    
    # Calculate summary statistics
    total_checks = violation_stats['total_checks'].sum()
    total_violations = violation_stats['violations'].sum()
    overall_rate = (total_violations / total_checks * 100) if total_checks > 0 else 0
    
    # Find most improving and deteriorating
    if not trend_df.empty:
        most_improving = trend_df.nsmallest(3, 'trend')
        most_deteriorating = trend_df.nlargest(3, 'trend')
    
    summary_text = f"""
    OVERALL STATISTICS
    
    Total Checks: {total_checks:,}
    Total Violations: {total_violations:,}
    Overall Violation Rate: {overall_rate:.2f}%
    
    Countries Analyzed: {len(violation_stats['country'].unique())}
    Rules Checked: {len(violation_stats['rule_code'].unique())}
    Years Covered: {violation_stats['year'].min():.0f} - {violation_stats['year'].max():.0f}
    """
    
    if not trend_df.empty:
        summary_text += f"""
    
    TREND ANALYSIS
    
    Most Improving:
    """
        for _, row in most_improving.iterrows():
            summary_text += f"\n  • {row['country']} - {row['rule']}: {row['trend']:.1f}% per year"
        
        summary_text += f"""
    
    Most Deteriorating:
    """
        for _, row in most_deteriorating.iterrows():
            summary_text += f"\n  • {row['country']} - {row['rule']}: +{row['trend']:.1f}% per year"
    
    ax6.text(0.1, 0.9, summary_text, transform=ax6.transAxes, fontsize=11,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.suptitle('Comprehensive Violation Analysis Overview', fontsize=20, fontweight='bold')
    plt.tight_layout()
    plt.savefig('plots/violation_overview.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Created violation_overview.png")

def create_additional_insights(df, violation_stats):
    """Create additional insightful analyses"""
    
    print("\n=== CREATING ADDITIONAL INSIGHTS ===")
    
    # 1. Domain size vs violation rate analysis
    create_size_violation_analysis(df)
    
    # 2. Rule correlation analysis
    create_rule_correlation_analysis(df)
    
    # 3. Temporal patterns
    create_temporal_patterns(df)
    
    # 4. Worst offenders analysis
    create_worst_offenders_analysis(df)

def create_size_violation_analysis(df):
    """Analyze relationship between page size and violations"""
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Bin sizes for analysis
    df['size_kb'] = df['size'] / 1024
    df['size_category'] = pd.cut(df['size_kb'], 
                                 bins=[0, 10, 50, 100, 500, float('inf')],
                                 labels=['<10KB', '10-50KB', '50-100KB', '100-500KB', '>500KB'])
    
    # Calculate violation rates by size category
    size_violations = df.groupby('size_category')['is_violation'].agg(['mean', 'count']).reset_index()
    size_violations['violation_rate'] = size_violations['mean'] * 100
    
    # Plot 1: Violation rate by size category
    ax1.bar(size_violations['size_category'], size_violations['violation_rate'], 
            color='skyblue', edgecolor='navy')
    ax1.set_title('Violation Rate by Page Size', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Page Size Category')
    ax1.set_ylabel('Violation Rate (%)')
    ax1.grid(True, alpha=0.3, axis='y')
    
    # Add count labels
    for i, (cat, rate, count) in enumerate(zip(size_violations['size_category'], 
                                               size_violations['violation_rate'], 
                                               size_violations['count'])):
        ax1.text(i, rate + 1, f'n={count}', ha='center', va='bottom', fontsize=9)
    
    # Plot 2: Scatter plot of size vs violations by rule
    ax2.set_xscale('log')
    
    for rule in df['rule_code'].unique()[:5]:  # Top 5 rules
        rule_data = df[df['rule_code'] == rule]
        violation_data = rule_data[rule_data['is_violation'] == 1]
        
        ax2.scatter(violation_data['size_kb'], 
                   np.random.normal(0, 0.1, len(violation_data)), 
                   alpha=0.3, s=20, label=rule)
    
    ax2.set_title('Page Size Distribution for Violations (Top 5 Rules)', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Page Size (KB, log scale)')
    ax2.set_ylabel('Jittered for visibility')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('plots/size_violation_analysis.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Created size_violation_analysis.png")

def create_rule_correlation_analysis(df):
    """Analyze correlations between different rule violations"""
    
    # Create pivot table of violations by website and rule
    violation_pivot = df.pivot_table(
        index=['country', 'hostname', 'timestamp'], 
        columns='rule_code', 
        values='is_violation',
        fill_value=0
    )
    
    # Calculate correlation matrix
    correlation_matrix = violation_pivot.corr()
    
    # Create visualization
    plt.figure(figsize=(12, 10))
    
    # Create mask for upper triangle
    mask = np.triu(np.ones_like(correlation_matrix), k=1)
    
    # Create heatmap
    sns.heatmap(correlation_matrix, 
                mask=mask,
                annot=True, 
                fmt='.2f', 
                cmap='coolwarm', 
                center=0,
                square=True,
                linewidths=0.5,
                cbar_kws={"shrink": 0.8, "label": "Correlation Coefficient"})
    
    plt.title('Rule Violation Correlation Matrix\n(How often rules are violated together)', 
              fontsize=16, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig('plots/rule_correlation_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Created rule_correlation_matrix.png")

def create_temporal_patterns(df):
    """Analyze temporal patterns in violations"""
    
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    
    # Extract month and day of week if possible
    if pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['month'] = df['timestamp'].dt.month
        df['day_of_week'] = df['timestamp'].dt.day_name()
        
        # Plot 1: Violations by month
        monthly_violations = df.groupby('month')['is_violation'].agg(['mean', 'count']).reset_index()
        monthly_violations['violation_rate'] = monthly_violations['mean'] * 100
        
        ax1.plot(monthly_violations['month'], monthly_violations['violation_rate'], 
                marker='o', linewidth=2, markersize=8, color='coral')
        ax1.set_title('Violation Rate by Month', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Month')
        ax1.set_ylabel('Violation Rate (%)')
        ax1.set_xticks(range(1, 13))
        ax1.grid(True, alpha=0.3)
    else:
        ax1.text(0.5, 0.5, 'Monthly analysis not available\n(timestamps not in datetime format)', 
                ha='center', va='center', transform=ax1.transAxes, fontsize=12)
        ax1.set_title('Violation Rate by Month', fontsize=14, fontweight='bold')
    
    # Plot 2: Yearly progression
    yearly_progression = df.groupby(['year', 'rule_code'])['is_violation'].mean().reset_index()
    yearly_progression['violation_rate'] = yearly_progression['is_violation'] * 100
    
    pivot_yearly = yearly_progression.pivot(index='year', columns='rule_code', values='violation_rate')
    
    for col in pivot_yearly.columns[:5]:  # Top 5 rules
        ax2.plot(pivot_yearly.index, pivot_yearly[col], marker='o', label=col, linewidth=2)
    
    ax2.set_title('Yearly Violation Rate Progression (Top 5 Rules)', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Violation Rate (%)')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    # Plot 3: Cumulative violations over time
    df_sorted = df.sort_values('timestamp')
    df_sorted['cumulative_violations'] = df_sorted['is_violation'].cumsum()
    df_sorted['cumulative_checks'] = range(1, len(df_sorted) + 1)
    df_sorted['cumulative_rate'] = df_sorted['cumulative_violations'] / df_sorted['cumulative_checks'] * 100
    
    # Sample for plotting (every 1000th point)
    sample_indices = range(0, len(df_sorted), max(1, len(df_sorted) // 1000))
    
    ax3.plot(df_sorted.iloc[sample_indices]['timestamp'], 
             df_sorted.iloc[sample_indices]['cumulative_rate'],
             linewidth=2, color='green')
    ax3.set_title('Cumulative Violation Rate Over Time', fontsize=14, fontweight='bold')
    ax3.set_xlabel('Time')
    ax3.set_ylabel('Cumulative Violation Rate (%)')
    ax3.grid(True, alpha=0.3)
    
    # Plot 4: Violation distribution by year
    ax4.violinplot([df[df['year'] == year]['is_violation'].values * 100 
                    for year in sorted(df['year'].unique())],
                   positions=sorted(df['year'].unique()),
                   showmeans=True)
    ax4.set_title('Violation Rate Distribution by Year', fontsize=14, fontweight='bold')
    ax4.set_xlabel('Year')
    ax4.set_ylabel('Violation Rate (%)')
    ax4.grid(True, alpha=0.3, axis='y')
    
    plt.suptitle('Temporal Patterns in Web Violations', fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig('plots/temporal_patterns.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Created temporal_patterns.png")

def create_worst_offenders_analysis(df):
    """Identify and visualize worst offending domains"""
    
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    
    # Calculate violation statistics by domain
    domain_stats = df.groupby('domain').agg({
        'is_violation': ['sum', 'count', 'mean'],
        'country': 'first',
        'year': lambda x: f"{x.min():.0f}-{x.max():.0f}"
    }).reset_index()
    
    domain_stats.columns = ['domain', 'total_violations', 'total_checks', 
                           'violation_rate', 'country', 'years']
    
    # Filter domains with at least 10 checks
    domain_stats = domain_stats[domain_stats['total_checks'] >= 10]
    
    # Plot 1: Top 15 worst offenders
    worst_offenders = domain_stats.nlargest(15, 'total_violations')
    
    y_pos = np.arange(len(worst_offenders))
    bars = ax1.barh(y_pos, worst_offenders['total_violations'], color='#FF6B6B')
    ax1.set_yticks(y_pos)
    ax1.set_yticklabels([f"{row['domain']} ({row['country']})" 
                         for _, row in worst_offenders.iterrows()], fontsize=9)
    ax1.set_title('Top 15 Domains by Total Violations', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Total Violations')
    ax1.grid(True, alpha=0.3, axis='x')
    
    # Add violation rate as text
    for i, (_, row) in enumerate(worst_offenders.iterrows()):
        ax1.text(row['total_violations'] + 1, i, 
                f"{row['violation_rate']*100:.1f}%", 
                va='center', fontsize=8)
    
    # Plot 2: Highest violation rates (min 20 checks)
    high_rate_domains = domain_stats[domain_stats['total_checks'] >= 20].nlargest(15, 'violation_rate')
    
    y_pos = np.arange(len(high_rate_domains))
    bars = ax2.barh(y_pos, high_rate_domains['violation_rate'] * 100, color='#FFA07A')
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels([f"{row['domain']} ({row['country']})" 
                         for _, row in high_rate_domains.iterrows()], fontsize=9)
    ax2.set_title('Top 15 Domains by Violation Rate (min 20 checks)', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Violation Rate (%)')
    ax2.grid(True, alpha=0.3, axis='x')
    ax2.set_xlim(0, 105)
    
    # Add check count as text
    for i, (_, row) in enumerate(high_rate_domains.iterrows()):
        ax2.text(row['violation_rate'] * 100 + 1, i, 
                f"n={row['total_checks']}", 
                va='center', fontsize=8)
    
    # Plot 3: Country distribution of worst offenders
    country_violations = df.groupby('country').agg({
        'is_violation': ['sum', 'count', 'mean']
    }).reset_index()
    country_violations.columns = ['country', 'total_violations', 'total_checks', 'violation_rate']
    country_violations = country_violations.sort_values('total_violations', ascending=False)
    
    ax3.bar(country_violations['country'], country_violations['total_violations'], 
            color='lightcoral', edgecolor='darkred')
    ax3.set_title('Total Violations by Country', fontsize=14, fontweight='bold')
    ax3.set_xlabel('Country')
    ax3.set_ylabel('Total Violations')
    ax3.grid(True, alpha=0.3, axis='y')
    
    # Add violation rate as text on bars
    for i, (_, row) in enumerate(country_violations.iterrows()):
        ax3.text(i, row['total_violations'] + 50, 
                f"{row['violation_rate']*100:.1f}%", 
                ha='center', va='bottom', fontsize=9)
    
    # Plot 4: Rule violation breakdown for worst domains
    worst_domain_names = worst_offenders['domain'].head(5).tolist()
    worst_domain_data = df[df['domain'].isin(worst_domain_names)]
    
    rule_breakdown = worst_domain_data.groupby(['domain', 'rule_code'])['is_violation'].sum().reset_index()
    pivot_breakdown = rule_breakdown.pivot(index='domain', columns='rule_code', values='is_violation')
    pivot_breakdown = pivot_breakdown.fillna(0)
    
    pivot_breakdown.plot(kind='bar', stacked=True, ax=ax4, colormap='tab20')
    ax4.set_title('Rule Violation Breakdown for Top 5 Worst Domains', fontsize=14, fontweight='bold')
    ax4.set_xlabel('Domain')
    ax4.set_ylabel('Number of Violations')
    ax4.legend(title='Rule Code', bbox_to_anchor=(1.05, 1), loc='upper left')
    ax4.grid(True, alpha=0.3, axis='y')
    
    plt.suptitle('Worst Offenders Analysis', fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig('plots/worst_offenders_analysis.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Created worst_offenders_analysis.png")

def save_detailed_reports(df, violation_stats):
    """Save detailed CSV reports for further analysis"""
    
    print("\n=== SAVING DETAILED REPORTS ===")
    
    # 1. Violation trends by country and year
    country_year_report = violation_stats.groupby(['country', 'year']).agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    country_year_report['violation_rate'] = country_year_report['violations'] / country_year_report['total_checks'] * 100
    country_year_report.to_csv('reports/violation_trends_by_country_year.csv', index=False)
    
    # 2. Rule performance report
    rule_report = violation_stats.groupby(['rule_code', 'rule_name']).agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    rule_report['violation_rate'] = rule_report['violations'] / rule_report['total_checks'] * 100
    rule_report = rule_report.sort_values('violation_rate', ascending=False)
    rule_report.to_csv('reports/rule_performance.csv', index=False)
    
    # 3. Domain violation report
    domain_report = df.groupby(['domain', 'country']).agg({
        'is_violation': ['sum', 'count', 'mean']
    }).reset_index()
    domain_report.columns = ['domain', 'country', 'total_violations', 'total_checks', 'violation_rate']
    domain_report = domain_report.sort_values('total_violations', ascending=False)
    domain_report.to_csv('reports/domain_violations.csv', index=False)
    
    # 4. Yearly progression report
    yearly_report = violation_stats.pivot_table(
        index='year',
        columns='country',
        values='violation_rate',
        aggfunc='mean'
    ) * 100
    yearly_report.to_csv('reports/yearly_violation_rates.csv')
    
    print("✓ Saved detailed reports to reports/ directory")

def create_executive_summary(df, violation_stats):
    """Create an executive summary visualization"""
    
    fig = plt.figure(figsize=(20, 12))
    gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
    
    # Calculate key metrics
    total_checks = df.shape[0]
    total_violations = df['is_violation'].sum()
    overall_violation_rate = (total_violations / total_checks * 100) if total_checks > 0 else 0
    
    countries = df['country'].nunique()
    domains = df['domain'].nunique()
    rules = df['rule_code'].nunique()
    years = sorted(df['year'].unique())
    
    # Main metrics panel
    ax_main = fig.add_subplot(gs[0, :])
    ax_main.axis('off')
    
    metrics_text = f"""
    WEB COMPLIANCE VIOLATION ANALYSIS - EXECUTIVE SUMMARY
    
    SCOPE OF ANALYSIS:
    • Total Checks Performed: {total_checks:,}
    • Total Violations Found: {total_violations:,}
    • Overall Violation Rate: {overall_violation_rate:.2f}%
    • Countries Analyzed: {countries}
    • Unique Domains: {domains:,}
    • Compliance Rules: {rules}
    • Time Period: {min(years):.0f} - {max(years):.0f}
    """
    
    ax_main.text(0.05, 0.5, metrics_text, transform=ax_main.transAxes, 
                fontsize=14, verticalalignment='center',
                bbox=dict(boxstyle='round,pad=1', facecolor='lightblue', alpha=0.8))
    
    # Trend summary
    ax_trend = fig.add_subplot(gs[1, 0])
    
    yearly_summary = violation_stats.groupby('year').agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    yearly_summary['rate'] = yearly_summary['violations'] / yearly_summary['total_checks'] * 100
    
    ax_trend.plot(yearly_summary['year'], yearly_summary['rate'], 
                 marker='o', linewidth=3, markersize=10, color='darkred')
    ax_trend.fill_between(yearly_summary['year'], yearly_summary['rate'], 
                         alpha=0.3, color='red')
    ax_trend.set_title('Overall Violation Rate Trend', fontsize=14, fontweight='bold')
    ax_trend.set_xlabel('Year')
    ax_trend.set_ylabel('Violation Rate (%)')
    ax_trend.grid(True, alpha=0.3)
    
    # Country performance
    ax_country = fig.add_subplot(gs[1, 1])
    
    country_summary = violation_stats.groupby('country').agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    country_summary['rate'] = country_summary['violations'] / country_summary['total_checks'] * 100
    country_summary = country_summary.sort_values('rate', ascending=False)
    
    colors = ['red' if rate > overall_violation_rate else 'green' 
              for rate in country_summary['rate']]
    
    bars = ax_country.bar(country_summary['country'], country_summary['rate'], color=colors)
    ax_country.axhline(y=overall_violation_rate, color='black', linestyle='--', 
                       label=f'Overall Rate ({overall_violation_rate:.1f}%)')
    ax_country.set_title('Violation Rates by Country', fontsize=14, fontweight='bold')
    ax_country.set_ylabel('Violation Rate (%)')
    ax_country.legend()
    ax_country.grid(True, alpha=0.3, axis='y')
    
    # Rule severity
    ax_rules = fig.add_subplot(gs[1, 2])
    
    rule_summary = violation_stats.groupby('rule_code').agg({
        'violations': 'sum',
        'total_checks': 'sum'
    }).reset_index()
    rule_summary['rate'] = rule_summary['violations'] / rule_summary['total_checks'] * 100
    rule_summary = rule_summary.sort_values('rate', ascending=False).head(10)
    
    ax_rules.barh(rule_summary['rule_code'], rule_summary['rate'], 
                  color=plt.cm.Reds(rule_summary['rate'] / 100))
    ax_rules.set_title('Top 10 Most Violated Rules', fontsize=14, fontweight='bold')
    ax_rules.set_xlabel('Violation Rate (%)')
    ax_rules.grid(True, alpha=0.3, axis='x')
    
    # Key insights
    ax_insights = fig.add_subplot(gs[2, :])
    ax_insights.axis('off')
    
    # Calculate insights
    improving_countries = []
    deteriorating_countries = []
    
    for country in violation_stats['country'].unique():
        country_data = violation_stats[violation_stats['country'] == country]
        yearly_rates = country_data.groupby('year').agg({
            'violations': 'sum',
            'total_checks': 'sum'
        }).reset_index()
        yearly_rates['rate'] = yearly_rates['violations'] / yearly_rates['total_checks'] * 100
        
        if len(yearly_rates) >= 2:
            first_year_rate = yearly_rates.iloc[0]['rate']
            last_year_rate = yearly_rates.iloc[-1]['rate']
            change = last_year_rate - first_year_rate
            
            if change < -5:  # More than 5% improvement
                improving_countries.append((country, change))
            elif change > 5:  # More than 5% deterioration
                deteriorating_countries.append((country, change))
    
    improving_countries.sort(key=lambda x: x[1])
    deteriorating_countries.sort(key=lambda x: x[1], reverse=True)
    
    insights_text = "KEY INSIGHTS:\n\n"
    
    if improving_countries:
        insights_text += "Most Improved Countries:\n"
        for country, change in improving_countries[:3]:
            insights_text += f"  • {country}: {change:.1f}% improvement\n"
    
    if deteriorating_countries:
        insights_text += "\nCountries Needing Attention:\n"
        for country, change in deteriorating_countries[:3]:
            insights_text += f"  • {country}: +{change:.1f}% increase in violations\n"
    
    # Most common violations
    top_violations = rule_summary.head(3)
    insights_text += "\nMost Common Violations:\n"
    for _, row in top_violations.iterrows():
        insights_text += f"  • {row['rule_code']}: {row['rate']:.1f}% violation rate\n"
    
    ax_insights.text(0.05, 0.8, insights_text, transform=ax_insights.transAxes,
                    fontsize=12, verticalalignment='top',
                    bbox=dict(boxstyle='round,pad=1', facecolor='lightyellow', alpha=0.8))
    
    plt.suptitle('Web Compliance Violations - Executive Summary', 
                fontsize=20, fontweight='bold')
    plt.tight_layout()
    plt.savefig('plots/executive_summary.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Created executive_summary.png")

def main():
    """Main function to run the enhanced analysis"""
    
    print("=== ENHANCED VIOLATION TREND ANALYZER ===")
    
    db_path = sys.argv[1] if len(sys.argv) > 1 else "results.db"
    
    # Create output directories
    for dir_name in ['plots', 'reports']:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        print(f"Successfully connected to {db_path}")
        
        # Extract violation data
        df = extract_violation_data(conn)
        
        if df is None or df.empty:
            print("No violation data found in database")
            return
        
        print(f"\nAnalyzing {len(df)} violation checks")
        print(f"Countries: {sorted(df['country'].unique())}")
        print(f"Years: {sorted(df['year'].unique())}")
        print(f"Rules: {sorted(df['rule_code'].unique())}")
        
        # Create violation trend analysis
        violation_stats = create_violation_trends_by_country(df)
        
        # Create additional insights
        create_additional_insights(df, violation_stats)
        
        # Create executive summary
        create_executive_summary(df, violation_stats)
        
        # Save detailed reports
        save_detailed_reports(df, violation_stats)
        
        print("\n=== ANALYSIS COMPLETE ===")
        print("Generated outputs:")
        print("- plots/ directory with all visualization files")
        print("- reports/ directory with detailed CSV reports")
        print("\nKey files:")
        print("- plots/executive_summary.png - High-level overview")
        print("- plots/violation_overview.png - Comprehensive analysis")
        print("- plots/violation_trends_[COUNTRY].png - Country-specific trends")
        print("- reports/violation_trends_by_country_year.csv - Detailed data")
        
    except Exception as e:
        print(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    main()