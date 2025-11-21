#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'

ALLOWED_SEVERITIES = %w[info warning critical page].freeze
DEFAULT_ALERT_DIR = File.expand_path('../../docs/observability/alerts', __dir__)

def validate_rule(file, group_idx, rule_idx, rule, errors)
  unless rule.is_a?(Hash)
    errors << format('%<file>s: group[%<group>d].rules[%<rule>d] must be a mapping', file: file, group: group_idx, rule: rule_idx)
    return
  end

  alert = rule['alert']
  if !alert.is_a?(String) || alert.strip.empty?
    errors << format('%<file>s: group[%<group>d].rules[%<rule>d] is missing an alert name', file: file, group: group_idx, rule: rule_idx)
  end

  expr = rule['expr']
  if !expr.is_a?(String) || expr.strip.empty?
    errors << format('%<file>s: %<alert>s expr must be a non-empty string', file: file, alert: alert || 'unnamed alert')
  end

  labels = rule['labels']
  unless labels.is_a?(Hash)
    errors << format('%<file>s: %<alert>s must define labels', file: file, alert: alert || 'unnamed alert')
  else
    severity = labels['severity']
    if !severity.is_a?(String) || severity.strip.empty?
      errors << format('%<file>s: %<alert>s severity label is required', file: file, alert: alert || 'unnamed alert')
    elsif !ALLOWED_SEVERITIES.include?(severity)
      errors << format('%<file>s: %<alert>s severity "%<severity>s" is not one of %<allowed>s', file: file, alert: alert || 'unnamed alert', severity: severity, allowed: ALLOWED_SEVERITIES.join(', '))
    end
  end

  annotations = rule['annotations']
  unless annotations.is_a?(Hash)
    errors << format('%<file>s: %<alert>s must define annotations', file: file, alert: alert || 'unnamed alert')
    return
  end

  %w[summary description].each do |field|
    value = annotations[field]
    if !value.is_a?(String) || value.strip.empty?
      errors << format('%<file>s: %<alert>s annotations.%<field>s is required', file: file, alert: alert || 'unnamed alert', field: field)
    end
  end

  runbook = annotations['runbook_url']
  if runbook && (!runbook.is_a?(String) || runbook.strip.empty?)
    errors << format('%<file>s: %<alert>s annotations.runbook_url must be a string when present', file: file, alert: alert || 'unnamed alert')
  end
end

alert_dir = ARGV[0] ? File.expand_path(ARGV[0], Dir.pwd) : DEFAULT_ALERT_DIR
unless Dir.exist?(alert_dir)
  warn "alert directory not found: #{alert_dir}"
  exit 1
end

files = Dir.glob(File.join(alert_dir, '*.yaml')).sort
if files.empty?
  warn "no Prometheus rule files found in #{alert_dir}"
  exit 1
end

errors = []

files.each do |file|
  begin
    data = YAML.safe_load(File.read(file), permitted_classes: [], permitted_symbols: [], aliases: true)
  rescue Psych::SyntaxError => e
    errors << format('%<file>s: %<error>s', file: file, error: e.message.split('\n').first)
    next
  end

  unless data.is_a?(Hash)
    errors << format('%<file>s: top-level document must be a mapping', file: file)
    next
  end

  spec = data['spec']
  groups = if spec.is_a?(Hash)
             spec['groups']
           else
             data['groups']
           end

  unless groups.is_a?(Array) && !groups.empty?
    errors << format('%<file>s: spec.groups or groups must be a non-empty array', file: file)
    next
  end

  groups.each_with_index do |group, group_idx|
    unless group.is_a?(Hash)
      errors << format('%<file>s: group[%<group>d] must be a mapping', file: file, group: group_idx)
      next
    end

    rules = group['rules']
    unless rules.is_a?(Array) && !rules.empty?
      errors << format('%<file>s: group[%<group>d].rules must be a non-empty array', file: file, group: group_idx)
      next
    end

    rules.each_with_index do |rule, rule_idx|
      validate_rule(file, group_idx, rule_idx, rule, errors)
    end
  end
end

if errors.empty?
  puts "Validated #{files.length} Prometheus rule file(s)"
  exit 0
end

errors.each { |msg| warn msg }
exit 1
