import { AnalysisRequest, AnalysisResponse } from "../types/analysis";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

export const analyzeEmail = async (payload: AnalysisRequest): Promise<AnalysisResponse> => {
  const response = await fetch(`${BASE_URL}/api/v1/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let errorDetail = `Analysis failed with status ${response.status}`;
    try {
      const errData = await response.json();
      if (errData.detail) {
        errorDetail = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
      }
    } catch {
      // Fallback
    }
    throw new Error(errorDetail);
  }

  return response.json();
};

export const checkHealth = async (): Promise<{ status: string }> => {
  const response = await fetch(`${BASE_URL}/health`);
  if (!response.ok) {
    throw new Error(`Health check returned status ${response.status}`);
  }
  return response.json();
};

export const checkMlHealth = async (): Promise<{ available: boolean; status: string; threshold?: number }> => {
  const response = await fetch(`${BASE_URL}/api/v1/health/ml`);
  if (!response.ok) {
    throw new Error(`ML health check returned status ${response.status}`);
  }
  return response.json();
};
