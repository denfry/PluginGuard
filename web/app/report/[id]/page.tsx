"use client";

import { use } from "react";
import { ReportClient } from "@/components/ReportClient";

export default function ReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  return <ReportClient id={id} />;
}
