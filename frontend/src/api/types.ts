import { z } from 'zod';

const id = z.uuid();
const date = z.iso.datetime({ offset: true });
const nullableText = z.string().nullable();
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const nonnegative = z.number().int().nonnegative();
export const scanStatusSchema = z.enum([
  'queued',
  'running',
  'completed',
  'failed',
]);
export const severitySchema = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN',
]);
export type Severity = z.infer<typeof severitySchema>;
export type ScanStatus = z.infer<typeof scanStatusSchema>;
export interface PageRequest {
  limit: number;
  offset: number;
}

export const scanRecordSchema = z.object({
  scan_id: id,
  image_reference: z.string(),
  status: scanStatusSchema,
});
export const scanDetailsSchema = scanRecordSchema.extend({
  created_at: date,
  started_at: date.nullable(),
  completed_at: date.nullable(),
  digest: digest.nullable(),
  platform: nullableText,
  scanner_name: nullableText,
  scanner_version: nullableText,
  scanner_database_metadata: z.record(z.string(), z.unknown()).nullable(),
  error_details: nullableText,
  mock: z.boolean(),
});
export const scanAcceptedSchema = z.object({
  scan_id: id,
  status: scanStatusSchema,
  status_url: z.string().regex(/^\/api\/v1\/scans\/[a-f0-9-]+$/i),
});
export const findingSchema = z.object({
  vulnerability_id: z.string(),
  package_name: z.string(),
  installed_version: z.string(),
  fixed_version: nullableText,
  severity: severitySchema,
  title: z.string(),
});
function page<T extends z.ZodType>(item: T) {
  return z
    .object({
      items: z.array(item),
      total: nonnegative,
      limit: z.number().int().min(1).max(100),
      offset: nonnegative,
    })
    .refine((value) => value.items.length <= value.limit);
}
export const scanHistorySchema = page(scanRecordSchema);
export const findingPageSchema = page(findingSchema).extend({
  mock: z.boolean(),
});
export type ScanRecord = z.infer<typeof scanRecordSchema>;
export type ScanDetails = z.infer<typeof scanDetailsSchema>;
export type ScanAccepted = z.infer<typeof scanAcceptedSchema>;
export type ScanHistory = z.infer<typeof scanHistorySchema>;
export type FindingPage = z.infer<typeof findingPageSchema>;
export interface ScanSubmission {
  image_reference: string;
}

export const policyRulesSchema = z.object({
  max_critical: nonnegative.max(2147483647),
  max_high: nonnegative.max(2147483647),
  require_sbom: z.boolean(),
  unknown_severity_action: z.enum(['fail', 'ignore']),
});
export const policyRecordSchema = z.object({
  policy_id: id,
  name: z.string(),
  created_at: date,
});
export const policyVersionSchema = z.object({
  policy_id: id,
  policy_version_id: id,
  version_number: z.number().int().positive(),
  rules: policyRulesSchema,
  created_at: date,
});
export const policyPageSchema = page(policyRecordSchema);
export const policyVersionPageSchema = page(policyVersionSchema);
export type PolicyRules = z.infer<typeof policyRulesSchema>;
export type PolicyRecord = z.infer<typeof policyRecordSchema>;
export type PolicyVersionRecord = z.infer<typeof policyVersionSchema>;
export type PolicyPage = z.infer<typeof policyPageSchema>;
export type PolicyVersionPage = z.infer<typeof policyVersionPageSchema>;
export interface PolicyCreate {
  name: string;
  rules: PolicyRules;
}
export interface PolicyVersionCreate {
  rules: PolicyRules;
}

const ruleValue = z.union([z.number().int(), z.boolean(), z.string()]);
const ruleExplanationSchema = z.object({
  rule_id: z.enum([
    'max_critical',
    'max_high',
    'require_sbom',
    'unknown_severity_action',
  ]),
  passed: z.boolean(),
  actual: ruleValue,
  expected: ruleValue,
  reason: z.string(),
});
const countsSchema = z.object({
  CRITICAL: nonnegative,
  HIGH: nonnegative,
  MEDIUM: nonnegative,
  LOW: nonnegative,
  UNKNOWN: nonnegative,
});
export const evaluationSchema = z.object({
  evaluation_id: id,
  scan_id: id,
  policy_id: id,
  policy_version_id: id,
  version_number: z.number().int().positive(),
  rule_snapshot: policyRulesSchema,
  evaluator_version: z.number().int().positive(),
  outcome: z.enum(['passed', 'failed', 'error']),
  counts: countsSchema,
  rules: z.array(ruleExplanationSchema),
  created_at: date,
  error_code: z.literal('invalid_evidence').nullable(),
  error_details: nullableText,
});
export const evaluationPageSchema = page(evaluationSchema);
export type RuleExplanation = z.infer<typeof ruleExplanationSchema>;
export type EvaluationRecord = z.infer<typeof evaluationSchema>;
export type EvaluationPage = z.infer<typeof evaluationPageSchema>;
export interface EvaluationRequest {
  policy_version_id: string;
}

export const sbomMetadataSchema = z.object({
  scan_id: id,
  status: z.enum(['pending', 'not_generated', 'available', 'failed']),
  format: nullableText,
  format_version: nullableText,
  scanner_version: nullableText,
  pinned_reference: nullableText,
  digest: digest.nullable(),
  platform: nullableText,
  size_bytes: nonnegative.nullable(),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .nullable(),
  created_at: date.nullable(),
  error_code: nullableText,
  error_details: nullableText,
});
export type SbomMetadata = z.infer<typeof sbomMetadataSchema>;
