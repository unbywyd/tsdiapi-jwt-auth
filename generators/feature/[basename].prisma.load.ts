import { PrismaOperation, usePrismaHook } from "@tsdiapi/prisma";

import { Prisma } from "@generated/prisma/client.js";
import { Container } from "typedi";
import CryptoService from "@tsdiapi/crypto";

usePrismaHook(Prisma.ModelName['Admin'], PrismaOperation.Create, async (payload) => {
    const cryptoService = Container.get(CryptoService);
    const data = payload.data;
    if (data.password) {
        const password = cryptoService.hashPassword(data.password);
        payload.data.password = password;
    }
    return payload;
});

usePrismaHook(Prisma.ModelName['Admin'], PrismaOperation.Update, async (payload) => {
    const cryptoService = Container.get(CryptoService);
    const data = payload.data;
    if (data.password) {
        const password = cryptoService.hashPassword(data.password);
        payload.data.password = password;
    }
    return payload;
});
