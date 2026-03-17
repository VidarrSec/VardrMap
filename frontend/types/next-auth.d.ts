import "next-auth";

declare module "next-auth" {
  interface Session {
    backendToken: string;
    user: {
      name?: string | null;
      email?: string | null;
      image?: string | null;
      githubId: string;
      username: string;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    githubId?: string;
    username?: string;
    backendToken?: string;
  }
}