import { createServerSupabaseClient } from "@/lib/supabase/server";

import SignupForm from "@/features/auth/components/SignupForm";
import AlreadySignedIn from "@/features/auth/components/AlreadySignedIn";

export default async function SignUpPage() {
  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) {
    const { data: profile } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", user.id)
      .single();
    return (
      <AlreadySignedIn
        email={user.email ?? "Unknown"}
        role={(profile?.role as string) ?? "Unknown"}
      />
    );
  }

  return <SignupForm />;
}
