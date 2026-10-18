import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient };

const isDev =
  typeof process !== 'undefined' && process.env?.NODE_ENV
    ? process.env.NODE_ENV === 'development'
    : (import.meta as any).env?.DEV ?? false;

export const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    log: isDev ? ['query', 'error', 'warn'] : ['error'],
  });

const isProd =
  typeof process !== 'undefined' && process.env?.NODE_ENV
    ? process.env.NODE_ENV === 'production'
    : (import.meta as any).env?.PROD ?? true;

if (!isProd) globalForPrisma.prisma = prisma;

export default prisma;
