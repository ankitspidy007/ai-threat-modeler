const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };

function topThreats(data, count = 3) {
  return [...(data.threats || [])]
    .sort((a, b) => {
      const severityDelta = (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
      if (severityDelta !== 0) return severityDelta;
      return (b.risk_score || 0) - (a.risk_score || 0);
    })
    .slice(0, count);
}

export function answerAnalysisQuestion(question, data) {
  const text = (question || '').trim().toLowerCase();
  if (!text) {
    return {
      title: 'Ask about this analysis',
      answer: 'Try asking what to fix first, what changed, where the biggest auth risks are, or what assumptions are still weak.',
      bullets: [],
    };
  }

  const strongest = topThreats(data, 3);
  const assumptions = data.coverage?.assumptions || [];
  const domain = data.domain_context;
  const diff = data.diff_summary;

  if (text.includes('fix first') || text.includes('priority')) {
    return {
      title: 'Recommended priority order',
      answer: strongest.length
        ? 'Start with the highest-severity confirmed findings that touch exposed components or sensitive data paths.'
        : 'There are no standout high-priority findings in the current result.',
      bullets: strongest.map((threat) => `${threat.severity}: ${threat.title}`),
    };
  }

  if (text.includes('change') || text.includes('changed') || text.includes('delta')) {
    return {
      title: 'What changed',
      answer: diff
        ? diff.changed
          ? 'This run introduced meaningful movement compared with the previous analysis.'
          : 'No meaningful risk delta was detected compared with the previous analysis.'
        : 'There is no prior analysis to compare against yet.',
      bullets: diff?.changed
        ? [
            `Score delta: ${diff.score_delta > 0 ? '+' : ''}${diff.score_delta || 0}`,
            `New threats: ${diff.new_threats?.length || 0}`,
            `Resolved threats: ${diff.resolved_threats?.length || 0}`,
          ]
        : [],
    };
  }

  if (text.includes('auth') || text.includes('identity') || text.includes('authorization')) {
    const authThreats = (data.threats || []).filter((threat) =>
      `${threat.title} ${threat.description} ${threat.category}`.toLowerCase().match(/auth|identity|oauth|jwt|rbac|access/)
    );
    return {
      title: 'Identity and access readout',
      answer: authThreats.length
        ? 'These findings most directly affect authentication, authorization, or identity trust.'
        : 'The current run did not surface many identity-specific findings, though assumptions may still hide auth gaps.',
      bullets: authThreats.slice(0, 4).map((threat) => `${threat.severity}: ${threat.title}`),
    };
  }

  if (text.includes('missing') || text.includes('unknown') || text.includes('assumption')) {
    return {
      title: 'Missing architectural detail',
      answer: assumptions.length
        ? 'These assumptions are still influencing the model and are good candidates for follow-up with the team.'
        : 'The model does not currently show major missing-detail assumptions.',
      bullets: assumptions.slice(0, 4).map((item) => item.message),
    };
  }

  if (text.includes('domain') || text.includes('special') || text.includes('industry')) {
    return {
      title: domain?.label || 'Domain guidance',
      answer: domain?.headline || 'No domain-specific guidance was attached to this run.',
      bullets: domain?.priority_controls || [],
    };
  }

  return {
    title: 'Analysis summary',
    answer: data.summary || 'Analysis complete.',
    bullets: strongest.map((threat) => `${threat.severity}: ${threat.title}`),
  };
}
