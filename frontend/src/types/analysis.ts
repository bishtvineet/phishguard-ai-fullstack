export type AuthStatus = "pass" | "fail" | "none" | "unknown";

export type RiskCategory = "Low Risk" | "Suspicious" | "High Risk" | "Inconclusive";

export type FindingSeverity = "info" | "low" | "medium" | "high";

export interface Finding {
  analyzer: string;
  indicator: string;
  description: string;
  severity: FindingSeverity;
  target?: string | null;
}

export interface EmailAuthenticationInput {
  spf: AuthStatus;
  dkim: AuthStatus;
  dmarc: AuthStatus;
}

export interface AnalysisRequest {
  sender_email: string;
  reply_to?: string | null;
  subject?: string;
  body?: string;
  additional_urls?: string[];
  authentication?: EmailAuthenticationInput;
}

export interface AnalysisResponse {
  risk_score: number | null;
  risk_category: RiskCategory;
  summary: string;
  findings: Finding[];
  recommendations: string[];
}

export interface SystemHealth {
  apiOnline: boolean;
  mlOnline: boolean;
  mlStatus: string;
  mlThreshold: number | null;
}
