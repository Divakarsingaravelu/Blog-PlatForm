import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import prisma from "@/lib/prisma";
import bcrypt from "bcryptjs";

export const authOptions = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text", placeholder: "email@example.com" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials) return null;
        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        });
        if (user && (await bcrypt.compare(credentials.password, user.passwordHash))) {
          return { id: user.id.toString(), name: user.name ?? "", email: user.email };
        }
        return null;
      },
    }),
  ],
  secret: process.env.NEXTAUTH_SECRET,
  callbacks: {
    async session({ session, token }) {
      if (session.user) {
        // @ts-ignore – we add custom id field
        session.user.id = token.sub;
      }
      return session;
    },
  },
};

export const GET = (req: Request) => NextAuth(req, authOptions);
export const POST = (req: Request) => NextAuth(req, authOptions);
