import { GnapClient, GnapRARItem } from "./gnap-lib";

export interface QrPolicy {
  needPin?: string;
  claimLimit: number;
  claims: {
    active: boolean;
    client: GnapClient;
  }[];
  access: GnapRARItem<"shclink-read">[];
}

export interface QrPolicy_CreateRequestBody {
  needPin?: string;
  claimLimit: number;
  locations: string[];
}