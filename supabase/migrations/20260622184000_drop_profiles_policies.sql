-- Drop ALL policies on profiles to isolate the recursion issue
DROP POLICY IF EXISTS "Users can read own profile" ON public.profiles;
DROP POLICY IF EXISTS "Admin/teacher can read all profiles" ON public.profiles;
DROP POLICY IF EXISTS "Admin/teacher can update any profile" ON public.profiles;
DROP POLICY IF EXISTS "Admins can read all profiles" ON public.profiles;
DROP POLICY IF EXISTS "Admins can update any profile" ON public.profiles;
