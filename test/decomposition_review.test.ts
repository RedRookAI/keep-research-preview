import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  advanceDecompositionReview,
  decompositionReviewDigest,
  initialDecompositionReviewState,
  type DecompositionReviewActionV1,
  type DecompositionReviewStateV1,
  type TrustedCandidateScopeV1,
  type TrustedReviewerContextV1,
} from "../src/decomposition/decomposition_review.js";

const H = (value: string) => value.repeat(64).slice(0, 64);
const G = (value: string) => `sha256:${H(value)}`;
const canonical = (value: unknown): string => Array.isArray(value)
  ? `[${value.map(canonical).join(",")}]`
  : value !== null && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`
    : JSON.stringify(value);
const digest = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
const CLOSURES = {
  "PG-04-T002": { role: "TICKET_BODIES_AND_BOUNDS", closure_bytes: Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDAyIiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImZmOTEzYjk1ZmI0ZmMyY2I0NjAzYWUwODFkYTk4NDc3N2IzNzI3MTU0OTY1YWYzNTMzNTRkZDMzYTU3YzBkMzAiLAogICJwcm9kdWN0X2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAicGxhbm5pbmdfY29tbWl0IjogImJmMGM4YzIyMGQ4YTM3OTIwMzBmZWExOGUyMTM0YzU1NjVmNjAyZGEiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI3NjA5NDE3ZjA1NTE2OTI4ZGQyYzg4NGE3ZDkyYmE1Yjc3ZGIwNTcxYzJmZjliMGNhMWU2ODdlMGU2NzViMjA2IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxLAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjE5NjJiODAwZWFlZjg3Yjc3MDA1MTE2ZmI1ZmU4NzE2ODI4MTVlMzE3ODcyYzYyY2QxNjVkMWQ2ZGIwYTY3ODAiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDIsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiODQwNTkxYmIxMDM1NDMzYmNkYjA2ZWM3NmViOTUyYTQ1NDI0ZTEyNzE2NTg0MzlhODAxOGM5MjE5NDFhMmM5YiIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMywKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI1N2JlNGIyNDI0YTc5NGFhZTEyOGZhYmVmZDRhZmE0MWI1YmM1Mzc0YTdiOWI2ZWEyYWVlZWY1M2RkNGVlZmRiIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA0LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjllMjc3ZDZiMDljNTE0MTM5Zjk2YmQxM2Y5MTc0ZDA3YWZmNThkNzM4ZTdjMjhlYTFhMmIwYmQ5YmRkMzU5MzYiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDUsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiYmFmZWYyYWRjNWI3OTViODhhMjE5NDQ5OWNhNWNmNWZlNTI1YzcxNDg4MWRmN2MyYzZmNzNjZTg0YTUxY2VkNSIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogNiwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI2YzNhMzA4ZjNlNGRiYTVkZjM3OTg1YjIyMzQyNmRkNjA1N2UyOTcxMWEwZTY3ZmI0ZDBiNWM4NTk4NjM2NDhkIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA3LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjk3MGQ0MjdlMDBhOGY2NmUyYWJhOTM2ZDc5Y2Y2MmFlODFlNTkyMWFmNzA3NGFjYWQ4MTA0ZDE0NDk5NTdkMGIiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDgsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiZGE0ODY3NWRlMzM0NWEwZWQ1NWVlYzY4YjQwODViMTVkMDU5MmFmMTA2ZjA5YjQ2YmMwZThiMzM4NWJjYTMzMCIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogOSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIzMTNlY2I5NTNmZmJlYzlhYzA0YzY4NGU5NGQ3NTg1M2I3ZWJhYzYwODY3OWJmZWNhMjM0ZmQ2MmFhNjljM2QyIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIxYmQ4YzUzYWM0Njg4ZThhYzRjMmEzZjRiYzFhNmJhNDk5ZmRlOTY3MWI5ODJjNmU4YmZlNDI2NjYyYjhlMzY5IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICJjMjYzY2IyM2NiZjQ0NDg2MDdkMjg3OTRkZjU0NzY1Y2QwNGM2NWVjMTY2YmMxNmIwNThlZDJiNDRlN2I2YjYzIgogICAgfQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwMi1jbG9zdXJlLTIwMjYuMDkuMDMva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogIjc4OGYyNjk3ZTY1MmU3ZGI2MjJhYzc0Nzg5OWVmNmE2M2E2M2E1MjNlNjg0ZmE0NGJmMjViMmZiZmRkOTk5YjkiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICI3ODhmMjY5N2U2NTJlN2RiNjIyYWM3NDc4OTllZjZhNjNhNjNhNTIzZTY4NGZhNDRiZjI1YjJmYmZkZDk5OWI5IiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wM1QyMjoxNDozOSswMjowMCIKfQo=", "base64").toString("utf8"), closure_digest: "faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5", product_commit: "79676b4f9134a3b12af6af734eed3c48f23ffc22" },
  "PG-04-T003": { role: "GRAPH_AND_RECIPROCAL_COVERAGE", closure_bytes: Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDAzIiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImRiZWJjY2I5OTBjZWZlYzk4MDE2MTIyOTY0N2JhNTZmYzMwN2Q4Y2IwZDAwOGVjYzIyYmM1YmMyMmVhN2Y4NDIiLAogICJwcm9kdWN0X2NvbW1pdCI6ICI5Y2QyZTYyYjUwNWI2ZTYxMzk5YjcyYzlmY2Y4MDBhMzUwNDU3N2RlIiwKICAicGxhbm5pbmdfY29tbWl0IjogIjgxYmRkZWFiMDVhOGM2ZTRkZTdmMWZjOGQ1OTk0NGEzNjUzZjg5YjgiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAwLCAiZXZpZGVuY2VfZGlnZXN0IjogIjdhYTJmYWMzNTM1OGQ1M2YwMTc1ZDcxNTc2NDBmM2I5NThhNDI4YTVhNWI5YzE0ZGU3MWFhOTE3Nzk2MDAzNGQifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEsICJldmlkZW5jZV9kaWdlc3QiOiAiMmYwOGM0Nzg0OTU1ODZkYzYyNWE1M2QxYTE0YjM5OGNiMWUyODNlOTQ4ZjFmYzk4YmZjZTc3ZjMxMDAyM2U1YiJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogMiwgImV2aWRlbmNlX2RpZ2VzdCI6ICI5Nzg3NTkzNzc4NGQ4MGQ4ZTgwZTIwZWEwYjYxMTIxNjM0YjE3OGFkMGQ5ZTE1NWNhMTU1YTFlOTBmOTIzYjI4In0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAzLCAiZXZpZGVuY2VfZGlnZXN0IjogImFmNDQ2MmM2OTUwZGVmY2I2OWM2ZDI1ZmU5MzA3ODYwZjhjOWE3NGFmNTRkNGMxZjEwNTM1OGVhZjU1NGY3MzkifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDQsICJldmlkZW5jZV9kaWdlc3QiOiAiYzI3YTRiOWE1M2E5YzIxY2Y4MTQ4YTEyNTU5ODA5OGIxNmZjY2JkNWZmNjk1MDBmZGMxZTcxYTNkZTU1MzE3ZCJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogNSwgImV2aWRlbmNlX2RpZ2VzdCI6ICJjNTQ5ZTFjZDVhMWM2Zjk0YTFhMjA1ZTczYWZjZjE3YTVjNTQzNWMwNzE2MmFjYTM4YjM1OGNkOTdkNjE3ZDI1In0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA2LCAiZXZpZGVuY2VfZGlnZXN0IjogIjY2ZDdjZTk4YjBiZTA5Zjk5YTEwMmFmMTE3MjE2MDA5Y2FhYmQ0ZWQyYWNkZjU0YTQ1Mjk5MWNiMTljMmJkNzYifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDcsICJldmlkZW5jZV9kaWdlc3QiOiAiMzdhZmMwYTQxYTAyZmE5MmM3NmNiYzZmNmNmNDAyYTkzMWRiNzc5NDM0YjI3OWY0NDJiNWU0NjlhYjFhZmI4OCJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogOCwgImV2aWRlbmNlX2RpZ2VzdCI6ICI4NDViNDAzMzNiYjI2YTRmNjYwZWE0MTQwMGQ3MGQ1MDE4YWNhOTc3YjMxNGI5NjczYTBiMDJiMzM1ZThhNGNlIn0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA5LCAiZXZpZGVuY2VfZGlnZXN0IjogIjk0ZmVkNTcwNzg4ZjlmZDFiMDBiMGViMjQ3ZGY0MGU2ZWNjZDg2NjA4ZTIyNGRjMGIyZTZjYTU4OWFjNjE4ZDgifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEwLCAiZXZpZGVuY2VfZGlnZXN0IjogImZlNzYzZTUyMTFkYTJmZWY1N2E5ZDZjMTliMWJjMjUxNWY3NmRhOTQxMGU1MzAwY2U1MjE3NDg5OGU3NjQ1YWEifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDExLCAiZXZpZGVuY2VfZGlnZXN0IjogImI4OTdkOGM1MTFlNzIxNjkwNTllNjU1MmRjNjllOTY5ZDViMGNlMTlmZDNjOTM3NTcyOWVmMWJkYzgwYWY0YjUifQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICI5Y2QyZTYyYjUwNWI2ZTYxMzk5YjcyYzlmY2Y4MDBhMzUwNDU3N2RlIiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwMy1jbG9zdXJlLTIwMjYuMDkuMDMva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogImIyNDM5YzM0MmZlMzE5YTQwMDAzM2EyYWE1YmM2YjhiNzNhNTE2N2MzZTEwYzNjYmZhNzI4ZTZhYjllOWVhYjYiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICJiMjQzOWMzNDJmZTMxOWE0MDAwMzNhMmFhNWJjNmI4YjczYTUxNjdjM2UxMGMzY2JmYTcyOGU2YWI5ZTllYWI2IiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wM1QyMzo1Mzo0MSswMjowMCIKfQo=", "base64").toString("utf8"), closure_digest: "41268ed1843199a7cff0775176d702d2940a1b2c0698a2e4e0e588d79825b28d", product_commit: "9cd2e62b505b6e61399b72c9fcf800a3504577de" },
  "PG-04-T004": { role: "TRACK_ALLOCATION", closure_bytes: Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDA0IiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImI2OTRhZGJiYWY5OWQyZDVkODcyNGY5ZDJkNWRiMjYxNjAzMjBkNmIxZDc2OTBiNGUzMWFmMjA0YmEzMzNjZDIiLAogICJwcm9kdWN0X2NvbW1pdCI6ICJmMjczODY3NjVkMGE5NjQ0MTMyNDBhN2Q4ZTgyMWI4NTg0MDMxMWQ3IiwKICAicGxhbm5pbmdfY29tbWl0IjogImM3NDUxOTkzMTkwYTQwNmQyZDBlZmJlMjMzZGQxZjIyNTAyNjBiZGYiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAwLCAiZXZpZGVuY2VfZGlnZXN0IjogIjNiZGMwYjA3Y2RjNTljYTk4N2M1NTRkNGIxYTczNzkyYjU5YjA0NDk3MDdmY2RjMDAyOTUxZGMwZGNjMWMwZWUifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEsICJldmlkZW5jZV9kaWdlc3QiOiAiYzkwNDBkNmVhMzE0ZmMzYWRiYTZhY2NmZjBkZDc2YWNhMDY5M2I4MTc3MjA4NmRlOTZkYjAyY2U1YzU5N2E0NSJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogMiwgImV2aWRlbmNlX2RpZ2VzdCI6ICI0YzYzNWRlNDMwZGMwOWIwZjllMDgxNTVjZDQyMzI2MGIwOTQxNDA2NjQ0YWZlMDAzOWU1NGRmY2EyMTY0NzcwIn0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAzLCAiZXZpZGVuY2VfZGlnZXN0IjogImFmNDQ2MmM2OTUwZGVmY2I2OWM2ZDI1ZmU5MzA3ODYwZjhjOWE3NGFmNTRkNGMxZjEwNTM1OGVhZjU1NGY3MzkifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDQsICJldmlkZW5jZV9kaWdlc3QiOiAiOTM5ZDQ4Nzc3ODQyZGJiYWVhOTE2ZjcxNzdiODIyNTc4MWYzMjNiZGQ3YzAzYjBlMDc5MDZkNzdmNWNkNTljNyJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogNSwgImV2aWRlbmNlX2RpZ2VzdCI6ICJjOTJkNDdiM2YxNmI3YjQwODIyNzYzMDRjMWRiNWNkNGIyM2E2MGI0YzRjNmEyNTNmYzY4ZGZiMTM2YTEwZjBmIn0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA2LCAiZXZpZGVuY2VfZGlnZXN0IjogImViOTQ5ZDQ2ZjQyY2QxMmE2YzExN2FlZGRhYWQ3N2RmYzZkNGJmNjMwOGU1Y2ZhMDFlMDU5NDA4OWE5YWYxMTQifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDcsICJldmlkZW5jZV9kaWdlc3QiOiAiMWI1YjQ5OWZhMGM4YWU5NWM5ZDEwYjI1OTVmOTEyYzQxYjc0ZDczMjEzMThkZWM0MjY1MTMyNzU5NDk2OGVjNSJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogOCwgImV2aWRlbmNlX2RpZ2VzdCI6ICIxM2ViOTYxNGNlMmFjNzVjYjJjNGI5M2JlNTAxNDY3MGI0ZmQ0ODQyY2NmZjFlYzNhNjY0YzdjZDlmM2FlZmI3In0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA5LCAiZXZpZGVuY2VfZGlnZXN0IjogImViMWE0Nzg4NTA0MTZjMWE3YjJjZjc5MjRlZjY3MTA0ZGUzZjdlMzMyM2ZmYjc1ZjdiMjBhOTViNDAwMWQ5MTkifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEwLCAiZXZpZGVuY2VfZGlnZXN0IjogIjE5NWU0OGRkMjI4OTNmNThhOGQzNzE5NzI3MmM4NDEyZDUwMDEyZDQ2ODU5ZWVjNWEwOWIzYTQ1N2QzYzg0ZDEifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDExLCAiZXZpZGVuY2VfZGlnZXN0IjogImJlYWEyNjJhY2I2YzBjZGNiNDQzZGE0MDEwMjJlYjRmM2JlNzRjYzk3YThmMDJhYzAwOWNkYWFhZWE2OTc2NWEifQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICJmMjczODY3NjVkMGE5NjQ0MTMyNDBhN2Q4ZTgyMWI4NTg0MDMxMWQ3IiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwNC1jbG9zdXJlLTIwMjYuMDkuMDQva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogIjI0MjNlNWYxMDQyMWVjZDkyZGFmOGMwMjg0OWVjOTRmNTBiOThmN2FhZTM1YWIzNDM0ODRmYmVhMWI1NDM4ZDIiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICIyNDIzZTVmMTA0MjFlY2Q5MmRhZjhjMDI4NDllYzk0ZjUwYjk4ZjdhYWUzNWFiMzQzNDg0ZmJlYTFiNTQzOGQyIiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wNFQwMTozNzowMCswMjowMCIKfQo=", "base64").toString("utf8"), closure_digest: "452a60a757fca16df48f5137851e00c48ded8e0f844517089fc585ddc217f797", product_commit: "f27386765d0a964413240a7d8e821b85840311d7" },
} as const;
const closure = (ticket_id: keyof typeof CLOSURES, _role: typeof CLOSURES[keyof typeof CLOSURES]["role"]) => ({ ticket_id, ...CLOSURES[ticket_id] });

export const n1: TrustedReviewerContextV1 = { schema_version: 1, kind: "n1", reviewer_id: "claude-one", reviewer_family: "Anthropic Claude", custody_id: "local-custody", organization_services: "ABSENT" };
const enterprise: TrustedReviewerContextV1 = { schema_version: 1, kind: "enterprise", organization_id: "red-rook", actor_id: "claude-two", reviewer_id: "claude-two", reviewer_family: "Anthropic Claude", role_id: "independent-reviewer", separation_policy_id: "sod-1", custody_evidence_digest: H("c"), isolation_evidence_digest: H("d"), local_owner_substitution: false };

export function scope(): TrustedCandidateScopeV1 {
  return {
    schema_version: 1,
    status: "DECOMPOSITION_REVIEW_SCOPE_ADMITTED",
    generation: G("a"),
    approved_inventory_digest: "f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db",
    candidate_digest: H("1"),
    manifest_digest: H("2"),
    scope_digest: H("3"),
    candidate_author_id: "codex-writer",
    candidate_author_family: "OpenAI Codex",
    bounds: { maximum_files: 20, maximum_bytes: 1_000_000, maximum_cases: 14, maximum_minutes: 120 },
    disclosed_reviewers: [
      { reviewer_id: n1.reviewer_id, reviewer_family: n1.reviewer_family },
      { reviewer_id: enterprise.reviewer_id, reviewer_family: enterprise.reviewer_family },
    ],
    prerequisites: [closure("PG-04-T002", "TICKET_BODIES_AND_BOUNDS"), closure("PG-04-T003", "GRAPH_AND_RECIPROCAL_COVERAGE"), closure("PG-04-T004", "TRACK_ALLOCATION")],
  };
}

const seal = <T extends Record<string, unknown>>(value: T, field: string): T => {
  const copy = { ...value }; delete copy[field];
  return { ...value, [field]: digest(copy) };
};
export const attest = (state: DecompositionReviewStateV1, reviewer: TrustedReviewerContextV1, assessable = true) => seal({ schema_version: 1, kind: "ATTEST_ASSESSABLE", expected_generation: state.generation, reviewer_id: reviewer.reviewer_id, assessable, observed_files: 10, observed_bytes: 20_000, observed_cases: 14, estimated_minutes: 90, attestation_digest: H("0") }, "attestation_digest") as DecompositionReviewActionV1;
const begin = (state: DecompositionReviewStateV1) => ({ schema_version: 1, kind: "BEGIN_SUBSTANTIVE_REVIEW", expected_generation: state.generation, reviewer_id: state.active_reviewer_id }) as DecompositionReviewActionV1;
const review = (state: DecompositionReviewStateV1, verdict: "PASS" | "REVISE", findings: readonly string[] = []) => seal({ schema_version: 1, kind: "SUBMIT_REVIEW", expected_generation: state.generation, round: state.active_round, reviewer_id: state.active_reviewer_id, candidate_digest: state.candidate_digest, manifest_digest: state.manifest_digest, verdict, findings, predecessor_receipt_digest: state.receipt_head, receipt_digest: H("0") }, "receipt_digest") as DecompositionReviewActionV1;

function step(state: DecompositionReviewStateV1, action: DecompositionReviewActionV1, reviewer: TrustedReviewerContextV1, trusted = scope()): DecompositionReviewStateV1 {
  const result = advanceDecompositionReview(state, action, reviewer, trusted);
  assert.equal(result.advanced, true, result.code);
  assert(result.state);
  return result.state;
}

function openAndBegin(reviewer: TrustedReviewerContextV1, trusted = scope()): DecompositionReviewStateV1 {
  let state = initialDecompositionReviewState(trusted);
  state = step(state, attest(state, reviewer), reviewer, trusted);
  return step(state, begin(state), reviewer, trusted);
}

test("PG-04-T005-FC01 n=1 assessability opens Vet 1 and begin consumes it", () => {
  const trusted = scope(), before = structuredClone(trusted);
  let state = initialDecompositionReviewState(trusted);
  const opened = step(state, attest(state, n1), n1, trusted);
  assert.equal(opened.phase, "VET_1_OPEN"); assert.equal(opened.used_rounds, 0);
  state = step(opened, begin(opened), n1, trusted);
  assert.equal(state.used_rounds, 1); assert.deepEqual(trusted, before);
});

test("PG-04-T005-FC02 enterprise assessability requires attributed custody and isolation", () => {
  const state = initialDecompositionReviewState(scope());
  const opened = step(state, attest(state, enterprise), enterprise);
  assert.equal(opened.phase, "VET_1_OPEN"); assert.equal(opened.used_rounds, 0);
});

test("PG-04-T005-FC03 unassessable enters owner stop without consuming a round", () => {
  const state = initialDecompositionReviewState(scope());
  const result = advanceDecompositionReview(state, attest(state, n1, false), n1, scope());
  assert.equal(result.code, "DECOMPOSITION_NOT_REVIEWABLE"); assert.equal(result.owner_stop, "OWNER_DECISION");
  assert.equal(result.state?.phase, "OWNER_STOP"); assert.equal(result.state?.used_rounds, 0);
});

test("PG-04-T005-FC04 candidate author cannot attest, even when unassessable", () => {
  const trusted = scope(), author = { ...n1, reviewer_id: trusted.candidate_author_id, reviewer_family: trusted.candidate_author_family };
  const state = initialDecompositionReviewState(trusted);
  const result = advanceDecompositionReview(state, attest(state, author, false), author, trusted);
  assert.equal(result.code, "VET_RECEIPT_INVALID");
});

test("PG-04-T005-FC05 replayed receipt is refused", () => {
  const trusted = scope(); let state = openAndBegin(n1, trusted); const action = review(state, "PASS");
  state = step(state, action, n1, trusted);
  const replay = advanceDecompositionReview(state, action, n1, trusted);
  assert.equal(replay.code, "VET_RECEIPT_INVALID");
});

test("PG-04-T005-FC06 open material finding cannot pass", () => {
  const trusted = scope(), state = openAndBegin(n1, trusted);
  const result = advanceDecompositionReview(state, review(state, "PASS", ["M1"]), n1, trusted);
  assert.equal(result.code, "VET_FINDINGS_OPEN");
});

test("PG-04-T005-FC07 two distinct exact PASS rounds emit the disposition", () => {
  const trusted = scope(); let state = openAndBegin(n1, trusted); state = step(state, review(state, "PASS"), n1, trusted);
  state = step(state, attest(state, enterprise), enterprise, trusted); state = step(state, begin(state), enterprise, trusted); state = step(state, review(state, "PASS"), enterprise, trusted);
  assert.equal(state.phase, "COMPLETE"); assert.equal(state.used_rounds, 2); assert.equal(state.disposition?.schema_version, 1);
  assert.equal(state.disposition?.reviewers.length, 2); assert.equal(state.disposition?.open_findings.length, 0);
  assert(Object.isFrozen(state)); assert(Object.isFrozen(state.disposition));
});

test("PG-04-T005-FC08 / PG-05-T011-FC04 third vet is an owner decision", () => {
  const trusted = scope(); let state = openAndBegin(n1, trusted); state = step(state, review(state, "PASS"), n1, trusted); state = step(state, attest(state, enterprise), enterprise, trusted); state = step(state, begin(state), enterprise, trusted); state = step(state, review(state, "PASS"), enterprise, trusted);
  const result = advanceDecompositionReview(state, attest(state, n1), n1, trusted);
  assert.equal(result.code, "THIRD_VET_REQUIRES_OWNER"); assert.equal(result.owner_stop, "OWNER_DECISION");
  assert.equal(result.state?.phase, "OWNER_STOP");
});

test("PG-04-T005-FC09 repair-chain omission and a second repair are refused", () => {
  const trusted = scope(); let state = openAndBegin(n1, trusted); state = step(state, review(state, "REVISE", ["M1"]), n1, trusted);
  const repair = seal({ schema_version: 1, kind: "SUBMIT_REPAIR", expected_generation: state.generation, round: 1, reviewer_id: n1.reviewer_id, from_candidate_digest: state.candidate_digest, to_candidate_digest: H("4"), prior_receipt_digest: H("f"), addressed_findings: ["M1"], repair_digest: H("0") }, "repair_digest") as DecompositionReviewActionV1;
  assert.equal(advanceDecompositionReview(state, repair, n1, trusted).code, "VET_RECEIPT_INVALID");
  const valid = seal({ ...repair, prior_receipt_digest: state.receipt_head, repair_digest: H("0") }, "repair_digest") as DecompositionReviewActionV1;
  state = step(state, valid, n1, trusted);
  const second = seal({ ...valid, from_candidate_digest: state.candidate_digest, to_candidate_digest: H("5"), prior_receipt_digest: state.receipt_head, repair_digest: H("0") }, "repair_digest") as DecompositionReviewActionV1;
  assert.equal(advanceDecompositionReview(state, second, n1, trusted).code, "VET_RECEIPT_INVALID");
});

test("PG-04-T005-FC10 wrong reviewer family is refused on both tracks", () => {
  for (const reviewer of [n1, enterprise]) { const trusted = scope(), wrong = { ...reviewer, reviewer_family: trusted.candidate_author_family } as TrustedReviewerContextV1; (trusted.disclosed_reviewers as { reviewer_id: string; reviewer_family: string }[]).find((row) => row.reviewer_id === reviewer.reviewer_id)!.reviewer_family = trusted.candidate_author_family; const state = initialDecompositionReviewState(trusted); assert.equal(advanceDecompositionReview(state, attest(state, wrong), wrong, trusted).code, "VET_RECEIPT_INVALID"); }
});

test("PG-04-T005-FC11 undisclosed reviewer is refused on both tracks", () => {
  for (const reviewer of [n1, enterprise]) { const hidden = { ...reviewer, reviewer_id: "undisclosed" } as TrustedReviewerContextV1, state = initialDecompositionReviewState(scope()); assert.equal(advanceDecompositionReview(state, attest(state, hidden), hidden, scope()).code, "VET_RECEIPT_INVALID"); }
});

test("PG-04-T005-FC12 wrong-candidate receipt is refused", () => {
  const trusted = scope(), state = openAndBegin(n1, trusted), action = seal({ ...review(state, "PASS"), candidate_digest: H("f"), receipt_digest: H("0") }, "receipt_digest") as DecompositionReviewActionV1;
  assert.equal(advanceDecompositionReview(state, action, n1, trusted).code, "VET_RECEIPT_INVALID");
});

test("PG-04-T005-FC13 structural completeness cannot override semantic incoherence", () => {
  const trusted = scope(), state = openAndBegin(n1, trusted);
  assert.equal(advanceDecompositionReview(state, review(state, "REVISE", ["SEMANTIC_INCOHERENCE"]), n1, trusted).code, "VET_FINDINGS_OPEN");
});

test("PG-04-T005-FC14 deterministic reload resumes once and preserves authority", () => {
  const trusted = scope(), state = openAndBegin(n1, trusted), restored = structuredClone(state), action = review(restored, "PASS");
  const first = advanceDecompositionReview(restored, action, n1, trusted), second = advanceDecompositionReview(restored, action, n1, trusted);
  assert.deepEqual(first, second); assert.equal(first.state?.implementation_authorized, false); assert.equal(decompositionReviewDigest(first.state), decompositionReviewDigest(second.state));
});

test("hostile prerequisites, bounds, stale generation, unknown keys and input mutation fail closed", () => {
  const trusted = scope(), state = initialDecompositionReviewState(trusted);
  for (let index = 0; index < 3; index += 1) { const badClosure = structuredClone(trusted); badClosure.prerequisites[index]!.closure_digest = H("0"); const denied = advanceDecompositionReview(state, attest(state, n1), n1, badClosure); assert.equal(denied.code, "PREREQUISITE_AUTHORITY_INVALID"); assert.equal(denied.reason, "CLOSURE_DIGEST_MISMATCH"); }
  const superseded = structuredClone(trusted); (superseded as { generation: string }).generation = G("b");
  const generation = advanceDecompositionReview(state, attest(state, n1), n1, superseded); assert.equal(generation.code, "PREREQUISITE_AUTHORITY_INVALID"); assert.equal(generation.reason, "GENERATION_MISMATCH");
  const opened = step(state, attest(state, n1), n1, trusted), asEnterprise: TrustedReviewerContextV1 = { schema_version: 1, kind: "enterprise", organization_id: "red-rook", actor_id: n1.reviewer_id, reviewer_id: n1.reviewer_id, reviewer_family: n1.reviewer_family, role_id: "reviewer", separation_policy_id: "sod", custody_evidence_digest: H("c"), isolation_evidence_digest: H("d"), local_owner_substitution: false };
  assert.equal(advanceDecompositionReview(opened, begin(opened), asEnterprise, trusted).code, "VET_RECEIPT_INVALID");
  const enterpriseState = initialDecompositionReviewState(trusted), enterpriseOpened = step(enterpriseState, attest(enterpriseState, enterprise), enterprise, trusted), asN1: TrustedReviewerContextV1 = { schema_version: 1, kind: "n1", reviewer_id: enterprise.reviewer_id, reviewer_family: enterprise.reviewer_family, custody_id: "local", organization_services: "ABSENT" };
  assert.equal(advanceDecompositionReview(enterpriseOpened, begin(enterpriseOpened), asN1, trusted).code, "VET_RECEIPT_INVALID");
  const tooLarge = attest(state, n1) as Extract<DecompositionReviewActionV1, { kind: "ATTEST_ASSESSABLE" }>;
  const oversized = seal({ ...tooLarge, observed_files: 21, attestation_digest: H("0") }, "attestation_digest") as DecompositionReviewActionV1;
  assert.equal(advanceDecompositionReview(state, oversized, n1, trusted).code, "DECOMPOSITION_NOT_REVIEWABLE");
  const stale = seal({ ...attest(state, n1), expected_generation: G("f"), attestation_digest: H("0") }, "attestation_digest") as DecompositionReviewActionV1;
  assert.equal(advanceDecompositionReview(state, stale, n1, trusted).code, "STALE_DERIVATION");
  const unknown = { ...attest(state, n1), surprise: true } as unknown as DecompositionReviewActionV1;
  assert.equal(advanceDecompositionReview(state, unknown, n1, trusted).code, "MALFORMED_OR_UNKNOWN_FIELD");
  const torn = { ...state, used_rounds: 2 };
  assert.equal(advanceDecompositionReview(torn, attest(state, n1), n1, trusted).code, "MALFORMED_OR_UNKNOWN_FIELD");
  assert.deepEqual(trusted, scope());
});
