"use client";

import { useState } from "react";
import { Shield, LogOut } from "lucide-react";

import { Button } from "@/components/ui/button";
import { serverSignOut } from "@/features/auth/actions/authCookies";

export default function AlreadySignedIn({
  email,
  role,
}: {
  email: string;
  role: string;
}) {
  const [pending, setPending] = useState(false);

  async function handleSignOut() {
    setPending(true);
    await serverSignOut();
    window.location.href = "/";
  }

  return (
    <div className="flex min-h-[calc(100vh-140px)] flex-col items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-background">
      <div className="w-full max-w-sm flex flex-col items-center">
        <div className="w-full rounded-xl border border-gray-800 bg-[#1A1A1A]/80 backdrop-blur-md p-8 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 inset-x-0 h-[2px] bg-gradient-to-r from-transparent via-emerald-500 to-transparent opacity-50" />

          <div className="mb-8 flex flex-col items-center text-center">
            <div className="mb-4 rounded-full bg-emerald-950/50 p-3 ring-1 ring-emerald-500/20">
              <Shield className="h-6 w-6 text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]" />
            </div>
            <h1 className="font-heading text-2xl font-bold tracking-tight text-white">
              Already signed in
            </h1>
            <p className="mt-2 text-sm text-muted-foreground">
              You are signed in as <span className="font-medium text-emerald-400">{email}</span>
            </p>
            <p className="mt-1 text-xs text-gray-500">
              Role: {role}
            </p>
          </div>

          <div className="space-y-3">
            <Button
              onClick={handleSignOut}
              className="w-full bg-gradient-to-r from-red-500 to-red-700 text-white font-semibold shadow-[0_4px_14px_0_rgba(239,68,68,0.39)] hover:shadow-[0_6px_20px_rgba(239,68,68,0.23)] hover:from-red-400 hover:to-red-600 transition-all duration-200"
              disabled={pending}
            >
              <LogOut className="mr-2 h-4 w-4" />
              {pending ? "Signing out..." : "Sign out"}
            </Button>

            <p className="text-center text-xs text-gray-500">
              After signing out you can log in with a different account.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
