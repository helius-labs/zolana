import VerifiableEncryption.Circuit.Prelude
import VerifiableEncryption.Circuit.Field
import VerifiableEncryption.Circuit.Field6
import VerifiableEncryption.Circuit.Curve
import VerifiableEncryption.Circuit.Aes
import VerifiableEncryption.Circuit.Kdf

set_option linter.unusedVariables false

namespace ZolanaVE

variable [Fact (Nat.Prime Order)]

def FieldMulCheck_8_8_8 (A: List.Vector F 8) (B: List.Vector F 8) (Out: List.Vector F 8): Prop :=
    CheckPolynomial_16_hbeeafe4b vec![(A.get (0 : Fin 8)), (A.get (1 : Fin 8)), (A.get (2 : Fin 8)), (A.get (3 : Fin 8)), (A.get (4 : Fin 8)), (A.get (5 : Fin 8)), (A.get (6 : Fin 8)), (A.get (7 : Fin 8)), (B.get (0 : Fin 8)), (B.get (1 : Fin 8)), (B.get (2 : Fin 8)), (B.get (3 : Fin 8)), (B.get (4 : Fin 8)), (B.get (5 : Fin 8)), (B.get (6 : Fin 8)), (B.get (7 : Fin 8))] fun gate_0 =>
    Gates.eq (gate_0.get (0 : Fin 8)) (Out.get (0 : Fin 8)) ∧
    Gates.eq (gate_0.get (1 : Fin 8)) (Out.get (1 : Fin 8)) ∧
    Gates.eq (gate_0.get (2 : Fin 8)) (Out.get (2 : Fin 8)) ∧
    Gates.eq (gate_0.get (3 : Fin 8)) (Out.get (3 : Fin 8)) ∧
    Gates.eq (gate_0.get (4 : Fin 8)) (Out.get (4 : Fin 8)) ∧
    Gates.eq (gate_0.get (5 : Fin 8)) (Out.get (5 : Fin 8)) ∧
    Gates.eq (gate_0.get (6 : Fin 8)) (Out.get (6 : Fin 8)) ∧
    Gates.eq (gate_0.get (7 : Fin 8)) (Out.get (7 : Fin 8)) ∧
    True

def GuardedAdd_8_8_8_8_8_8 (PX: List.Vector F 8) (PY: List.Vector F 8) (QX: List.Vector F 8) (QY: List.Vector F 8) (RX: List.Vector F 8) (RY: List.Vector F 8): Prop :=
    AssertDistinctX_8_8_h689cdb88 PX QX ∧
    Add_8_8_8_8_h3f5cf0cd PX PY QX QY fun gate_1 =>
    Gates.eq ((gate_1.get (0 : Fin 2)).get (0 : Fin 8)) (RX.get (0 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (0 : Fin 8)) (RY.get (0 : Fin 8)) ∧
    Gates.eq ((gate_1.get (0 : Fin 2)).get (1 : Fin 8)) (RX.get (1 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (1 : Fin 8)) (RY.get (1 : Fin 8)) ∧
    Gates.eq ((gate_1.get (0 : Fin 2)).get (2 : Fin 8)) (RX.get (2 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (2 : Fin 8)) (RY.get (2 : Fin 8)) ∧
    Gates.eq ((gate_1.get (0 : Fin 2)).get (3 : Fin 8)) (RX.get (3 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (3 : Fin 8)) (RY.get (3 : Fin 8)) ∧
    Gates.eq ((gate_1.get (0 : Fin 2)).get (4 : Fin 8)) (RX.get (4 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (4 : Fin 8)) (RY.get (4 : Fin 8)) ∧
    Gates.eq ((gate_1.get (0 : Fin 2)).get (5 : Fin 8)) (RX.get (5 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (5 : Fin 8)) (RY.get (5 : Fin 8)) ∧
    Gates.eq ((gate_1.get (0 : Fin 2)).get (6 : Fin 8)) (RX.get (6 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (6 : Fin 8)) (RY.get (6 : Fin 8)) ∧
    Gates.eq ((gate_1.get (0 : Fin 2)).get (7 : Fin 8)) (RX.get (7 : Fin 8)) ∧
    Gates.eq ((gate_1.get (1 : Fin 2)).get (7 : Fin 8)) (RY.get (7 : Fin 8)) ∧
    True

def NativeSlopeGuard_8 (Lambda: List.Vector F 8) (Other: F): Prop :=
    AssertDistinctSlope_8_hf8ff5ddf Lambda Other ∧
    True

def AgreeKey_32_65_6_p1 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Packed: List.Vector F 6) (gate_72: F) (gate_80: F) (gate_88: F) (gate_96: F) (gate_104: F) (gate_112: F) (gate_120: F) (gate_128: F) (gate_136: F) (gate_144: F) (gate_152: F) (gate_160: F) (gate_168: F) (gate_176: F) (gate_184: F) (gate_192: F) (gate_198: F) (gate_199: F): Prop :=
    ∃gate_200, gate_200 = Gates.add gate_199 (RecipientPk.get (1 : Fin 65)) ∧
    ∃gate_201, gate_201 = Gates.mul gate_200 (256:F) ∧
    ∃gate_202, gate_202 = Gates.add gate_201 (RecipientPk.get (2 : Fin 65)) ∧
    ∃gate_203, gate_203 = Gates.mul gate_202 (256:F) ∧
    ∃gate_204, gate_204 = Gates.add gate_203 (RecipientPk.get (3 : Fin 65)) ∧
    ∃gate_205, gate_205 = Gates.mul gate_204 (256:F) ∧
    ∃gate_206, gate_206 = Gates.add gate_205 (RecipientPk.get (4 : Fin 65)) ∧
    ∃gate_207, gate_207 = Gates.mul gate_206 (256:F) ∧
    ∃gate_208, gate_208 = Gates.add gate_207 (RecipientPk.get (5 : Fin 65)) ∧
    ∃gate_209, gate_209 = Gates.mul gate_208 (256:F) ∧
    ∃gate_210, gate_210 = Gates.add gate_209 (RecipientPk.get (6 : Fin 65)) ∧
    ∃gate_211, gate_211 = Gates.mul gate_210 (256:F) ∧
    ∃gate_212, gate_212 = Gates.add gate_211 (RecipientPk.get (7 : Fin 65)) ∧
    ∃gate_213, gate_213 = Gates.mul gate_212 (256:F) ∧
    ∃gate_214, gate_214 = Gates.add gate_213 (RecipientPk.get (8 : Fin 65)) ∧
    ∃gate_215, gate_215 = Gates.mul gate_214 (256:F) ∧
    ∃gate_216, gate_216 = Gates.add gate_215 (RecipientPk.get (9 : Fin 65)) ∧
    ∃gate_217, gate_217 = Gates.mul gate_216 (256:F) ∧
    ∃gate_218, gate_218 = Gates.add gate_217 (RecipientPk.get (10 : Fin 65)) ∧
    ∃gate_219, gate_219 = Gates.mul gate_218 (256:F) ∧
    ∃gate_220, gate_220 = Gates.add gate_219 (RecipientPk.get (11 : Fin 65)) ∧
    ∃gate_221, gate_221 = Gates.mul gate_220 (256:F) ∧
    ∃gate_222, gate_222 = Gates.add gate_221 (RecipientPk.get (12 : Fin 65)) ∧
    ∃gate_223, gate_223 = Gates.mul gate_222 (256:F) ∧
    ∃gate_224, gate_224 = Gates.add gate_223 (RecipientPk.get (13 : Fin 65)) ∧
    ∃gate_225, gate_225 = Gates.mul gate_224 (256:F) ∧
    ∃gate_226, gate_226 = Gates.add gate_225 (RecipientPk.get (14 : Fin 65)) ∧
    ∃gate_227, gate_227 = Gates.mul gate_226 (256:F) ∧
    ∃gate_228, gate_228 = Gates.add gate_227 (RecipientPk.get (15 : Fin 65)) ∧
    ∃gate_229, gate_229 = Gates.mul gate_228 (256:F) ∧
    ∃gate_230, gate_230 = Gates.add gate_229 (RecipientPk.get (16 : Fin 65)) ∧
    ∃gate_231, gate_231 = Gates.mul gate_230 (256:F) ∧
    ∃gate_232, gate_232 = Gates.add gate_231 (RecipientPk.get (17 : Fin 65)) ∧
    ∃gate_233, gate_233 = Gates.mul gate_232 (256:F) ∧
    ∃gate_234, gate_234 = Gates.add gate_233 (RecipientPk.get (18 : Fin 65)) ∧
    ∃gate_235, gate_235 = Gates.mul gate_234 (256:F) ∧
    ∃gate_236, gate_236 = Gates.add gate_235 (RecipientPk.get (19 : Fin 65)) ∧
    ∃gate_237, gate_237 = Gates.mul gate_236 (256:F) ∧
    ∃gate_238, gate_238 = Gates.add gate_237 (RecipientPk.get (20 : Fin 65)) ∧
    ∃gate_239, gate_239 = Gates.mul gate_238 (256:F) ∧
    ∃gate_240, gate_240 = Gates.add gate_239 (RecipientPk.get (21 : Fin 65)) ∧
    ∃gate_241, gate_241 = Gates.mul gate_240 (256:F) ∧
    ∃gate_242, gate_242 = Gates.add gate_241 (RecipientPk.get (22 : Fin 65)) ∧
    ∃gate_243, gate_243 = Gates.mul gate_242 (256:F) ∧
    ∃gate_244, gate_244 = Gates.add gate_243 (RecipientPk.get (23 : Fin 65)) ∧
    ∃gate_245, gate_245 = Gates.mul gate_244 (256:F) ∧
    ∃gate_246, gate_246 = Gates.add gate_245 (RecipientPk.get (24 : Fin 65)) ∧
    ∃gate_247, gate_247 = Gates.mul gate_246 (256:F) ∧
    ∃gate_248, gate_248 = Gates.add gate_247 (RecipientPk.get (25 : Fin 65)) ∧
    ∃gate_249, gate_249 = Gates.mul gate_248 (256:F) ∧
    ∃gate_250, gate_250 = Gates.add gate_249 (RecipientPk.get (26 : Fin 65)) ∧
    ∃gate_251, gate_251 = Gates.mul gate_250 (256:F) ∧
    ∃gate_252, gate_252 = Gates.add gate_251 (RecipientPk.get (27 : Fin 65)) ∧
    ∃gate_253, gate_253 = Gates.mul gate_252 (256:F) ∧
    ∃gate_254, gate_254 = Gates.add gate_253 (RecipientPk.get (28 : Fin 65)) ∧
    ∃gate_255, gate_255 = Gates.mul gate_254 (256:F) ∧
    ∃gate_256, gate_256 = Gates.add gate_255 (RecipientPk.get (29 : Fin 65)) ∧
    ∃gate_257, gate_257 = Gates.mul gate_256 (256:F) ∧
    ∃gate_258, gate_258 = Gates.add gate_257 (RecipientPk.get (30 : Fin 65)) ∧
    ∃gate_259, gate_259 = Gates.add gate_198 gate_258 ∧
    ∃gate_260, gate_260 = Gates.mul (0:F) (256:F) ∧
    ∃gate_261, gate_261 = Gates.add gate_260 (RecipientPk.get (31 : Fin 65)) ∧
    ∃gate_262, gate_262 = Gates.mul gate_261 (256:F) ∧
    ∃gate_263, gate_263 = Gates.add gate_262 (RecipientPk.get (32 : Fin 65)) ∧
    RangeCheck 8 (EphemeralSk.get (0 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (1 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (2 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (3 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (4 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (5 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (6 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (7 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (8 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (9 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (10 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (11 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (12 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (13 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (14 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (15 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (16 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (17 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (18 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (19 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (20 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (21 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (22 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (23 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (24 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (25 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (26 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (27 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (28 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (29 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (30 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (31 : Fin 32)) ∧
    ∃gate_296, gate_296 = Gates.mul (0:F) (256:F) ∧
    ∃gate_297, gate_297 = Gates.add gate_296 (EphemeralSk.get (28 : Fin 32)) ∧
    ∃gate_298, gate_298 = Gates.mul gate_297 (256:F) ∧
    ∃gate_299, gate_299 = Gates.add gate_298 (EphemeralSk.get (29 : Fin 32)) ∧
    ∃gate_300, gate_300 = Gates.mul gate_299 (256:F) ∧
    ∃gate_301, gate_301 = Gates.add gate_300 (EphemeralSk.get (30 : Fin 32)) ∧
    ∃gate_302, gate_302 = Gates.mul gate_301 (256:F) ∧
    ∃gate_303, gate_303 = Gates.add gate_302 (EphemeralSk.get (31 : Fin 32)) ∧
    ∃gate_304, gate_304 = Gates.mul (0:F) (256:F) ∧
    ∃gate_305, gate_305 = Gates.add gate_304 (EphemeralSk.get (24 : Fin 32)) ∧
    ∃gate_306, gate_306 = Gates.mul gate_305 (256:F) ∧
    ∃gate_307, gate_307 = Gates.add gate_306 (EphemeralSk.get (25 : Fin 32)) ∧
    ∃gate_308, gate_308 = Gates.mul gate_307 (256:F) ∧
    ∃gate_309, gate_309 = Gates.add gate_308 (EphemeralSk.get (26 : Fin 32)) ∧
    ∃gate_310, gate_310 = Gates.mul gate_309 (256:F) ∧
    ∃gate_311, gate_311 = Gates.add gate_310 (EphemeralSk.get (27 : Fin 32)) ∧
    ∃gate_312, gate_312 = Gates.mul (0:F) (256:F) ∧
    ∃gate_313, gate_313 = Gates.add gate_312 (EphemeralSk.get (20 : Fin 32)) ∧
    ∃gate_314, gate_314 = Gates.mul gate_313 (256:F) ∧
    ∃gate_315, gate_315 = Gates.add gate_314 (EphemeralSk.get (21 : Fin 32)) ∧
    ∃gate_316, gate_316 = Gates.mul gate_315 (256:F) ∧
    ∃gate_317, gate_317 = Gates.add gate_316 (EphemeralSk.get (22 : Fin 32)) ∧
    ∃gate_318, gate_318 = Gates.mul gate_317 (256:F) ∧
    ∃gate_319, gate_319 = Gates.add gate_318 (EphemeralSk.get (23 : Fin 32)) ∧
    ∃gate_320, gate_320 = Gates.mul (0:F) (256:F) ∧
    ∃gate_321, gate_321 = Gates.add gate_320 (EphemeralSk.get (16 : Fin 32)) ∧
    ∃gate_322, gate_322 = Gates.mul gate_321 (256:F) ∧
    ∃gate_323, gate_323 = Gates.add gate_322 (EphemeralSk.get (17 : Fin 32)) ∧
    ∃gate_324, gate_324 = Gates.mul gate_323 (256:F) ∧
    ∃gate_325, gate_325 = Gates.add gate_324 (EphemeralSk.get (18 : Fin 32)) ∧
    ∃gate_326, gate_326 = Gates.mul gate_325 (256:F) ∧
    ∃gate_327, gate_327 = Gates.add gate_326 (EphemeralSk.get (19 : Fin 32)) ∧
    ∃gate_328, gate_328 = Gates.mul (0:F) (256:F) ∧
    ∃gate_329, gate_329 = Gates.add gate_328 (EphemeralSk.get (12 : Fin 32)) ∧
    ∃gate_330, gate_330 = Gates.mul gate_329 (256:F) ∧
    ∃gate_331, gate_331 = Gates.add gate_330 (EphemeralSk.get (13 : Fin 32)) ∧
    ∃gate_332, gate_332 = Gates.mul gate_331 (256:F) ∧
    ∃gate_333, gate_333 = Gates.add gate_332 (EphemeralSk.get (14 : Fin 32)) ∧
    ∃gate_334, gate_334 = Gates.mul gate_333 (256:F) ∧
    ∃gate_335, gate_335 = Gates.add gate_334 (EphemeralSk.get (15 : Fin 32)) ∧
    ∃gate_336, gate_336 = Gates.mul (0:F) (256:F) ∧
    ∃gate_337, gate_337 = Gates.add gate_336 (EphemeralSk.get (8 : Fin 32)) ∧
    ∃gate_338, gate_338 = Gates.mul gate_337 (256:F) ∧
    ∃gate_339, gate_339 = Gates.add gate_338 (EphemeralSk.get (9 : Fin 32)) ∧
    ∃gate_340, gate_340 = Gates.mul gate_339 (256:F) ∧
    ∃gate_341, gate_341 = Gates.add gate_340 (EphemeralSk.get (10 : Fin 32)) ∧
    ∃gate_342, gate_342 = Gates.mul gate_341 (256:F) ∧
    ∃gate_343, gate_343 = Gates.add gate_342 (EphemeralSk.get (11 : Fin 32)) ∧
    ∃gate_344, gate_344 = Gates.mul (0:F) (256:F) ∧
    ∃gate_345, gate_345 = Gates.add gate_344 (EphemeralSk.get (4 : Fin 32)) ∧
    ∃gate_346, gate_346 = Gates.mul gate_345 (256:F) ∧
    ∃gate_347, gate_347 = Gates.add gate_346 (EphemeralSk.get (5 : Fin 32)) ∧
    ∃gate_348, gate_348 = Gates.mul gate_347 (256:F) ∧
    ∃gate_349, gate_349 = Gates.add gate_348 (EphemeralSk.get (6 : Fin 32)) ∧
    ∃gate_350, gate_350 = Gates.mul gate_349 (256:F) ∧
    ∃gate_351, gate_351 = Gates.add gate_350 (EphemeralSk.get (7 : Fin 32)) ∧
    ∃gate_352, gate_352 = Gates.mul (0:F) (256:F) ∧
    ∃gate_353, gate_353 = Gates.add gate_352 (EphemeralSk.get (0 : Fin 32)) ∧
    ∃gate_354, gate_354 = Gates.mul gate_353 (256:F) ∧
    ∃gate_355, gate_355 = Gates.add gate_354 (EphemeralSk.get (1 : Fin 32)) ∧
    ∃gate_356, gate_356 = Gates.mul gate_355 (256:F) ∧
    ∃gate_357, gate_357 = Gates.add gate_356 (EphemeralSk.get (2 : Fin 32)) ∧
    ∃gate_358, gate_358 = Gates.mul gate_357 (256:F) ∧
    ∃gate_359, gate_359 = Gates.add gate_358 (EphemeralSk.get (3 : Fin 32)) ∧
    ScalarMulChecked_8_8_8_h9a706aba vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] vec![gate_303, gate_311, gate_319, gate_327, gate_335, gate_343, gate_351, gate_359] fun gate_360 =>
    ScalarMulBase_8_h3037b025 vec![gate_303, gate_311, gate_319, gate_327, gate_335, gate_343, gate_351, gate_359] fun gate_361 =>
    AssertCanonical_8_0_hcc2f8a19 (gate_361.get (0 : Fin 2)) ∧
    AssertCanonical_8_0_hcc2f8a19 (gate_361.get (1 : Fin 2)) ∧
    CompressedPacking_8_8_32 (gate_361.get (0 : Fin 2)) (gate_361.get (1 : Fin 2)) fun gate_364 =>
    AssertCanonical_8_0_hcc2f8a19 (gate_360.get (0 : Fin 2)) ∧
    SplitLowBits_8_32 ((gate_360.get (0 : Fin 2)).get (0 : Fin 8)) fun gate_366 =>
    ∃gate_367, gate_367 = Gates.mul ((gate_360.get (0 : Fin 2)).get (1 : Fin 8)) (16777216:F) ∧
    ∃gate_368, gate_368 = Gates.add (gate_366.get (0 : Fin 2)) gate_367 ∧
    ∃gate_369, gate_369 = Gates.mul ((gate_360.get (0 : Fin 2)).get (2 : Fin 8)) (72057594037927936:F) ∧
    ∃gate_370, gate_370 = Gates.add gate_368 gate_369 ∧
    ∃gate_371, gate_371 = Gates.mul ((gate_360.get (0 : Fin 2)).get (3 : Fin 8)) K_1 ∧
    ∃gate_372, gate_372 = Gates.add gate_370 gate_371 ∧
    ∃gate_373, gate_373 = Gates.mul ((gate_360.get (0 : Fin 2)).get (4 : Fin 8)) K_2 ∧
    ∃gate_374, gate_374 = Gates.add gate_372 gate_373 ∧
    ∃gate_375, gate_375 = Gates.mul ((gate_360.get (0 : Fin 2)).get (5 : Fin 8)) K_3 ∧
    ∃gate_376, gate_376 = Gates.add gate_374 gate_375 ∧
    ∃gate_377, gate_377 = Gates.mul ((gate_360.get (0 : Fin 2)).get (6 : Fin 8)) K_4 ∧
    ∃gate_378, gate_378 = Gates.add gate_376 gate_377 ∧
    ∃gate_379, gate_379 = Gates.mul ((gate_360.get (0 : Fin 2)).get (7 : Fin 8)) K_5 ∧
    ∃gate_380, gate_380 = Gates.add gate_378 gate_379 ∧
    Gates.eq gate_259 (Packed.get (0 : Fin 6)) ∧
    Gates.eq gate_263 (Packed.get (1 : Fin 6)) ∧
    Gates.eq (gate_364.get (0 : Fin 2)) (Packed.get (2 : Fin 6)) ∧
    Gates.eq (gate_364.get (1 : Fin 2)) (Packed.get (3 : Fin 6)) ∧
    Gates.eq gate_380 (Packed.get (4 : Fin 6)) ∧
    Gates.eq (gate_366.get (1 : Fin 2)) (Packed.get (5 : Fin 6)) ∧
    True

def AgreeKey_32_65_6 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Packed: List.Vector F 6): Prop :=
    Gates.eq (RecipientPk.get (0 : Fin 65)) (4:F) ∧
    RangeCheck 8 (RecipientPk.get (1 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (2 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (3 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (4 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (5 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (6 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (7 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (8 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (9 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (10 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (11 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (12 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (13 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (14 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (15 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (16 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (17 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (18 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (19 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (20 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (21 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (22 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (23 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (24 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (25 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (26 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (27 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (28 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (29 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (30 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (31 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (32 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (33 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (34 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (35 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (36 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (37 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (38 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (39 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (40 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (41 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (42 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (43 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (44 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (45 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (46 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (47 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (48 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (49 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (50 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (51 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (52 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (53 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (54 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (55 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (56 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (57 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (58 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (59 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (60 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (61 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (62 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (63 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (64 : Fin 65)) ∧
    ∃gate_65, gate_65 = Gates.mul (0:F) (256:F) ∧
    ∃gate_66, gate_66 = Gates.add gate_65 (RecipientPk.get (29 : Fin 65)) ∧
    ∃gate_67, gate_67 = Gates.mul gate_66 (256:F) ∧
    ∃gate_68, gate_68 = Gates.add gate_67 (RecipientPk.get (30 : Fin 65)) ∧
    ∃gate_69, gate_69 = Gates.mul gate_68 (256:F) ∧
    ∃gate_70, gate_70 = Gates.add gate_69 (RecipientPk.get (31 : Fin 65)) ∧
    ∃gate_71, gate_71 = Gates.mul gate_70 (256:F) ∧
    ∃gate_72, gate_72 = Gates.add gate_71 (RecipientPk.get (32 : Fin 65)) ∧
    ∃gate_73, gate_73 = Gates.mul (0:F) (256:F) ∧
    ∃gate_74, gate_74 = Gates.add gate_73 (RecipientPk.get (25 : Fin 65)) ∧
    ∃gate_75, gate_75 = Gates.mul gate_74 (256:F) ∧
    ∃gate_76, gate_76 = Gates.add gate_75 (RecipientPk.get (26 : Fin 65)) ∧
    ∃gate_77, gate_77 = Gates.mul gate_76 (256:F) ∧
    ∃gate_78, gate_78 = Gates.add gate_77 (RecipientPk.get (27 : Fin 65)) ∧
    ∃gate_79, gate_79 = Gates.mul gate_78 (256:F) ∧
    ∃gate_80, gate_80 = Gates.add gate_79 (RecipientPk.get (28 : Fin 65)) ∧
    ∃gate_81, gate_81 = Gates.mul (0:F) (256:F) ∧
    ∃gate_82, gate_82 = Gates.add gate_81 (RecipientPk.get (21 : Fin 65)) ∧
    ∃gate_83, gate_83 = Gates.mul gate_82 (256:F) ∧
    ∃gate_84, gate_84 = Gates.add gate_83 (RecipientPk.get (22 : Fin 65)) ∧
    ∃gate_85, gate_85 = Gates.mul gate_84 (256:F) ∧
    ∃gate_86, gate_86 = Gates.add gate_85 (RecipientPk.get (23 : Fin 65)) ∧
    ∃gate_87, gate_87 = Gates.mul gate_86 (256:F) ∧
    ∃gate_88, gate_88 = Gates.add gate_87 (RecipientPk.get (24 : Fin 65)) ∧
    ∃gate_89, gate_89 = Gates.mul (0:F) (256:F) ∧
    ∃gate_90, gate_90 = Gates.add gate_89 (RecipientPk.get (17 : Fin 65)) ∧
    ∃gate_91, gate_91 = Gates.mul gate_90 (256:F) ∧
    ∃gate_92, gate_92 = Gates.add gate_91 (RecipientPk.get (18 : Fin 65)) ∧
    ∃gate_93, gate_93 = Gates.mul gate_92 (256:F) ∧
    ∃gate_94, gate_94 = Gates.add gate_93 (RecipientPk.get (19 : Fin 65)) ∧
    ∃gate_95, gate_95 = Gates.mul gate_94 (256:F) ∧
    ∃gate_96, gate_96 = Gates.add gate_95 (RecipientPk.get (20 : Fin 65)) ∧
    ∃gate_97, gate_97 = Gates.mul (0:F) (256:F) ∧
    ∃gate_98, gate_98 = Gates.add gate_97 (RecipientPk.get (13 : Fin 65)) ∧
    ∃gate_99, gate_99 = Gates.mul gate_98 (256:F) ∧
    ∃gate_100, gate_100 = Gates.add gate_99 (RecipientPk.get (14 : Fin 65)) ∧
    ∃gate_101, gate_101 = Gates.mul gate_100 (256:F) ∧
    ∃gate_102, gate_102 = Gates.add gate_101 (RecipientPk.get (15 : Fin 65)) ∧
    ∃gate_103, gate_103 = Gates.mul gate_102 (256:F) ∧
    ∃gate_104, gate_104 = Gates.add gate_103 (RecipientPk.get (16 : Fin 65)) ∧
    ∃gate_105, gate_105 = Gates.mul (0:F) (256:F) ∧
    ∃gate_106, gate_106 = Gates.add gate_105 (RecipientPk.get (9 : Fin 65)) ∧
    ∃gate_107, gate_107 = Gates.mul gate_106 (256:F) ∧
    ∃gate_108, gate_108 = Gates.add gate_107 (RecipientPk.get (10 : Fin 65)) ∧
    ∃gate_109, gate_109 = Gates.mul gate_108 (256:F) ∧
    ∃gate_110, gate_110 = Gates.add gate_109 (RecipientPk.get (11 : Fin 65)) ∧
    ∃gate_111, gate_111 = Gates.mul gate_110 (256:F) ∧
    ∃gate_112, gate_112 = Gates.add gate_111 (RecipientPk.get (12 : Fin 65)) ∧
    ∃gate_113, gate_113 = Gates.mul (0:F) (256:F) ∧
    ∃gate_114, gate_114 = Gates.add gate_113 (RecipientPk.get (5 : Fin 65)) ∧
    ∃gate_115, gate_115 = Gates.mul gate_114 (256:F) ∧
    ∃gate_116, gate_116 = Gates.add gate_115 (RecipientPk.get (6 : Fin 65)) ∧
    ∃gate_117, gate_117 = Gates.mul gate_116 (256:F) ∧
    ∃gate_118, gate_118 = Gates.add gate_117 (RecipientPk.get (7 : Fin 65)) ∧
    ∃gate_119, gate_119 = Gates.mul gate_118 (256:F) ∧
    ∃gate_120, gate_120 = Gates.add gate_119 (RecipientPk.get (8 : Fin 65)) ∧
    ∃gate_121, gate_121 = Gates.mul (0:F) (256:F) ∧
    ∃gate_122, gate_122 = Gates.add gate_121 (RecipientPk.get (1 : Fin 65)) ∧
    ∃gate_123, gate_123 = Gates.mul gate_122 (256:F) ∧
    ∃gate_124, gate_124 = Gates.add gate_123 (RecipientPk.get (2 : Fin 65)) ∧
    ∃gate_125, gate_125 = Gates.mul gate_124 (256:F) ∧
    ∃gate_126, gate_126 = Gates.add gate_125 (RecipientPk.get (3 : Fin 65)) ∧
    ∃gate_127, gate_127 = Gates.mul gate_126 (256:F) ∧
    ∃gate_128, gate_128 = Gates.add gate_127 (RecipientPk.get (4 : Fin 65)) ∧
    ∃gate_129, gate_129 = Gates.mul (0:F) (256:F) ∧
    ∃gate_130, gate_130 = Gates.add gate_129 (RecipientPk.get (61 : Fin 65)) ∧
    ∃gate_131, gate_131 = Gates.mul gate_130 (256:F) ∧
    ∃gate_132, gate_132 = Gates.add gate_131 (RecipientPk.get (62 : Fin 65)) ∧
    ∃gate_133, gate_133 = Gates.mul gate_132 (256:F) ∧
    ∃gate_134, gate_134 = Gates.add gate_133 (RecipientPk.get (63 : Fin 65)) ∧
    ∃gate_135, gate_135 = Gates.mul gate_134 (256:F) ∧
    ∃gate_136, gate_136 = Gates.add gate_135 (RecipientPk.get (64 : Fin 65)) ∧
    ∃gate_137, gate_137 = Gates.mul (0:F) (256:F) ∧
    ∃gate_138, gate_138 = Gates.add gate_137 (RecipientPk.get (57 : Fin 65)) ∧
    ∃gate_139, gate_139 = Gates.mul gate_138 (256:F) ∧
    ∃gate_140, gate_140 = Gates.add gate_139 (RecipientPk.get (58 : Fin 65)) ∧
    ∃gate_141, gate_141 = Gates.mul gate_140 (256:F) ∧
    ∃gate_142, gate_142 = Gates.add gate_141 (RecipientPk.get (59 : Fin 65)) ∧
    ∃gate_143, gate_143 = Gates.mul gate_142 (256:F) ∧
    ∃gate_144, gate_144 = Gates.add gate_143 (RecipientPk.get (60 : Fin 65)) ∧
    ∃gate_145, gate_145 = Gates.mul (0:F) (256:F) ∧
    ∃gate_146, gate_146 = Gates.add gate_145 (RecipientPk.get (53 : Fin 65)) ∧
    ∃gate_147, gate_147 = Gates.mul gate_146 (256:F) ∧
    ∃gate_148, gate_148 = Gates.add gate_147 (RecipientPk.get (54 : Fin 65)) ∧
    ∃gate_149, gate_149 = Gates.mul gate_148 (256:F) ∧
    ∃gate_150, gate_150 = Gates.add gate_149 (RecipientPk.get (55 : Fin 65)) ∧
    ∃gate_151, gate_151 = Gates.mul gate_150 (256:F) ∧
    ∃gate_152, gate_152 = Gates.add gate_151 (RecipientPk.get (56 : Fin 65)) ∧
    ∃gate_153, gate_153 = Gates.mul (0:F) (256:F) ∧
    ∃gate_154, gate_154 = Gates.add gate_153 (RecipientPk.get (49 : Fin 65)) ∧
    ∃gate_155, gate_155 = Gates.mul gate_154 (256:F) ∧
    ∃gate_156, gate_156 = Gates.add gate_155 (RecipientPk.get (50 : Fin 65)) ∧
    ∃gate_157, gate_157 = Gates.mul gate_156 (256:F) ∧
    ∃gate_158, gate_158 = Gates.add gate_157 (RecipientPk.get (51 : Fin 65)) ∧
    ∃gate_159, gate_159 = Gates.mul gate_158 (256:F) ∧
    ∃gate_160, gate_160 = Gates.add gate_159 (RecipientPk.get (52 : Fin 65)) ∧
    ∃gate_161, gate_161 = Gates.mul (0:F) (256:F) ∧
    ∃gate_162, gate_162 = Gates.add gate_161 (RecipientPk.get (45 : Fin 65)) ∧
    ∃gate_163, gate_163 = Gates.mul gate_162 (256:F) ∧
    ∃gate_164, gate_164 = Gates.add gate_163 (RecipientPk.get (46 : Fin 65)) ∧
    ∃gate_165, gate_165 = Gates.mul gate_164 (256:F) ∧
    ∃gate_166, gate_166 = Gates.add gate_165 (RecipientPk.get (47 : Fin 65)) ∧
    ∃gate_167, gate_167 = Gates.mul gate_166 (256:F) ∧
    ∃gate_168, gate_168 = Gates.add gate_167 (RecipientPk.get (48 : Fin 65)) ∧
    ∃gate_169, gate_169 = Gates.mul (0:F) (256:F) ∧
    ∃gate_170, gate_170 = Gates.add gate_169 (RecipientPk.get (41 : Fin 65)) ∧
    ∃gate_171, gate_171 = Gates.mul gate_170 (256:F) ∧
    ∃gate_172, gate_172 = Gates.add gate_171 (RecipientPk.get (42 : Fin 65)) ∧
    ∃gate_173, gate_173 = Gates.mul gate_172 (256:F) ∧
    ∃gate_174, gate_174 = Gates.add gate_173 (RecipientPk.get (43 : Fin 65)) ∧
    ∃gate_175, gate_175 = Gates.mul gate_174 (256:F) ∧
    ∃gate_176, gate_176 = Gates.add gate_175 (RecipientPk.get (44 : Fin 65)) ∧
    ∃gate_177, gate_177 = Gates.mul (0:F) (256:F) ∧
    ∃gate_178, gate_178 = Gates.add gate_177 (RecipientPk.get (37 : Fin 65)) ∧
    ∃gate_179, gate_179 = Gates.mul gate_178 (256:F) ∧
    ∃gate_180, gate_180 = Gates.add gate_179 (RecipientPk.get (38 : Fin 65)) ∧
    ∃gate_181, gate_181 = Gates.mul gate_180 (256:F) ∧
    ∃gate_182, gate_182 = Gates.add gate_181 (RecipientPk.get (39 : Fin 65)) ∧
    ∃gate_183, gate_183 = Gates.mul gate_182 (256:F) ∧
    ∃gate_184, gate_184 = Gates.add gate_183 (RecipientPk.get (40 : Fin 65)) ∧
    ∃gate_185, gate_185 = Gates.mul (0:F) (256:F) ∧
    ∃gate_186, gate_186 = Gates.add gate_185 (RecipientPk.get (33 : Fin 65)) ∧
    ∃gate_187, gate_187 = Gates.mul gate_186 (256:F) ∧
    ∃gate_188, gate_188 = Gates.add gate_187 (RecipientPk.get (34 : Fin 65)) ∧
    ∃gate_189, gate_189 = Gates.mul gate_188 (256:F) ∧
    ∃gate_190, gate_190 = Gates.add gate_189 (RecipientPk.get (35 : Fin 65)) ∧
    ∃gate_191, gate_191 = Gates.mul gate_190 (256:F) ∧
    ∃gate_192, gate_192 = Gates.add gate_191 (RecipientPk.get (36 : Fin 65)) ∧
    AssertCanonical_8_0_hcc2f8a19 vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] ∧
    AssertCanonical_8_0_hcc2f8a19 vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] ∧
    AssertOnCurve_8_8_h2c0228bb vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] ∧
    SplitLowBits_1_8 (RecipientPk.get (64 : Fin 65)) fun gate_196 =>
    ∃gate_197, gate_197 = Gates.add (2:F) (gate_196.get (1 : Fin 2)) ∧
    ∃gate_198, gate_198 = Gates.mul gate_197 K_0 ∧
    ∃gate_199, gate_199 = Gates.mul (0:F) (256:F) ∧
    AgreeKey_32_65_6_p1 EphemeralSk RecipientPk Packed gate_72 gate_80 gate_88 gate_96 gate_104 gate_112 gate_120 gate_128 gate_136 gate_144 gate_152 gate_160 gate_168 gate_176 gate_184 gate_192 gate_198 gate_199

def DerivePublicKey_32_32_p1 (Sk: List.Vector F 32) (X: List.Vector F 32) (Lo: F) (Hi: F) (gate_188: List.Vector (List.Vector F 8) 2) (gate_192: List.Vector F 4) (gate_199: F): Prop :=
    ∃gate_200, gate_200 = Gates.add gate_199 (gate_192.get (1 : Fin 4)) ∧
    ∃gate_201, gate_201 = Gates.mul gate_200 (256:F) ∧
    ∃gate_202, gate_202 = Gates.add gate_201 (gate_192.get (2 : Fin 4)) ∧
    ∃gate_203, gate_203 = Gates.mul gate_202 (256:F) ∧
    ∃gate_204, gate_204 = Gates.add gate_203 (gate_192.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (7 : Fin 8)) gate_204 ∧
    ∃gate_206 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_206.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_206.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_206.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_206.get (3 : Fin 4)) ∧
    ∃gate_211, gate_211 = Gates.mul (0:F) (256:F) ∧
    ∃gate_212, gate_212 = Gates.add gate_211 (gate_206.get (0 : Fin 4)) ∧
    ∃gate_213, gate_213 = Gates.mul gate_212 (256:F) ∧
    ∃gate_214, gate_214 = Gates.add gate_213 (gate_206.get (1 : Fin 4)) ∧
    ∃gate_215, gate_215 = Gates.mul gate_214 (256:F) ∧
    ∃gate_216, gate_216 = Gates.add gate_215 (gate_206.get (2 : Fin 4)) ∧
    ∃gate_217, gate_217 = Gates.mul gate_216 (256:F) ∧
    ∃gate_218, gate_218 = Gates.add gate_217 (gate_206.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (6 : Fin 8)) gate_218 ∧
    ∃gate_220 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_220.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_220.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_220.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_220.get (3 : Fin 4)) ∧
    ∃gate_225, gate_225 = Gates.mul (0:F) (256:F) ∧
    ∃gate_226, gate_226 = Gates.add gate_225 (gate_220.get (0 : Fin 4)) ∧
    ∃gate_227, gate_227 = Gates.mul gate_226 (256:F) ∧
    ∃gate_228, gate_228 = Gates.add gate_227 (gate_220.get (1 : Fin 4)) ∧
    ∃gate_229, gate_229 = Gates.mul gate_228 (256:F) ∧
    ∃gate_230, gate_230 = Gates.add gate_229 (gate_220.get (2 : Fin 4)) ∧
    ∃gate_231, gate_231 = Gates.mul gate_230 (256:F) ∧
    ∃gate_232, gate_232 = Gates.add gate_231 (gate_220.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (5 : Fin 8)) gate_232 ∧
    ∃gate_234 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_234.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_234.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_234.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_234.get (3 : Fin 4)) ∧
    ∃gate_239, gate_239 = Gates.mul (0:F) (256:F) ∧
    ∃gate_240, gate_240 = Gates.add gate_239 (gate_234.get (0 : Fin 4)) ∧
    ∃gate_241, gate_241 = Gates.mul gate_240 (256:F) ∧
    ∃gate_242, gate_242 = Gates.add gate_241 (gate_234.get (1 : Fin 4)) ∧
    ∃gate_243, gate_243 = Gates.mul gate_242 (256:F) ∧
    ∃gate_244, gate_244 = Gates.add gate_243 (gate_234.get (2 : Fin 4)) ∧
    ∃gate_245, gate_245 = Gates.mul gate_244 (256:F) ∧
    ∃gate_246, gate_246 = Gates.add gate_245 (gate_234.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (4 : Fin 8)) gate_246 ∧
    ∃gate_248 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_248.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_248.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_248.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_248.get (3 : Fin 4)) ∧
    ∃gate_253, gate_253 = Gates.mul (0:F) (256:F) ∧
    ∃gate_254, gate_254 = Gates.add gate_253 (gate_248.get (0 : Fin 4)) ∧
    ∃gate_255, gate_255 = Gates.mul gate_254 (256:F) ∧
    ∃gate_256, gate_256 = Gates.add gate_255 (gate_248.get (1 : Fin 4)) ∧
    ∃gate_257, gate_257 = Gates.mul gate_256 (256:F) ∧
    ∃gate_258, gate_258 = Gates.add gate_257 (gate_248.get (2 : Fin 4)) ∧
    ∃gate_259, gate_259 = Gates.mul gate_258 (256:F) ∧
    ∃gate_260, gate_260 = Gates.add gate_259 (gate_248.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (3 : Fin 8)) gate_260 ∧
    ∃gate_262 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_262.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_262.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_262.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_262.get (3 : Fin 4)) ∧
    ∃gate_267, gate_267 = Gates.mul (0:F) (256:F) ∧
    ∃gate_268, gate_268 = Gates.add gate_267 (gate_262.get (0 : Fin 4)) ∧
    ∃gate_269, gate_269 = Gates.mul gate_268 (256:F) ∧
    ∃gate_270, gate_270 = Gates.add gate_269 (gate_262.get (1 : Fin 4)) ∧
    ∃gate_271, gate_271 = Gates.mul gate_270 (256:F) ∧
    ∃gate_272, gate_272 = Gates.add gate_271 (gate_262.get (2 : Fin 4)) ∧
    ∃gate_273, gate_273 = Gates.mul gate_272 (256:F) ∧
    ∃gate_274, gate_274 = Gates.add gate_273 (gate_262.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (2 : Fin 8)) gate_274 ∧
    ∃gate_276 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_276.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_276.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_276.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_276.get (3 : Fin 4)) ∧
    ∃gate_281, gate_281 = Gates.mul (0:F) (256:F) ∧
    ∃gate_282, gate_282 = Gates.add gate_281 (gate_276.get (0 : Fin 4)) ∧
    ∃gate_283, gate_283 = Gates.mul gate_282 (256:F) ∧
    ∃gate_284, gate_284 = Gates.add gate_283 (gate_276.get (1 : Fin 4)) ∧
    ∃gate_285, gate_285 = Gates.mul gate_284 (256:F) ∧
    ∃gate_286, gate_286 = Gates.add gate_285 (gate_276.get (2 : Fin 4)) ∧
    ∃gate_287, gate_287 = Gates.mul gate_286 (256:F) ∧
    ∃gate_288, gate_288 = Gates.add gate_287 (gate_276.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (1 : Fin 8)) gate_288 ∧
    ∃gate_290 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_290.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_290.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_290.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_290.get (3 : Fin 4)) ∧
    ∃gate_295, gate_295 = Gates.mul (0:F) (256:F) ∧
    ∃gate_296, gate_296 = Gates.add gate_295 (gate_290.get (0 : Fin 4)) ∧
    ∃gate_297, gate_297 = Gates.mul gate_296 (256:F) ∧
    ∃gate_298, gate_298 = Gates.add gate_297 (gate_290.get (1 : Fin 4)) ∧
    ∃gate_299, gate_299 = Gates.mul gate_298 (256:F) ∧
    ∃gate_300, gate_300 = Gates.add gate_299 (gate_290.get (2 : Fin 4)) ∧
    ∃gate_301, gate_301 = Gates.mul gate_300 (256:F) ∧
    ∃gate_302, gate_302 = Gates.add gate_301 (gate_290.get (3 : Fin 4)) ∧
    Gates.eq ((gate_188.get (0 : Fin 2)).get (0 : Fin 8)) gate_302 ∧
    CompressedPacking_8_8_32 (gate_188.get (0 : Fin 2)) (gate_188.get (1 : Fin 2)) fun gate_304 =>
    Gates.eq (gate_304.get (0 : Fin 2)) Lo ∧
    Gates.eq (gate_304.get (1 : Fin 2)) Hi ∧
    SplitLowBits_1_32 ((gate_188.get (1 : Fin 2)).get (0 : Fin 8)) fun gate_307 =>
    ∃_ignored_, _ignored_ = Gates.add (2:F) (gate_307.get (1 : Fin 2)) ∧
    Gates.eq (gate_192.get (0 : Fin 4)) (X.get (0 : Fin 32)) ∧
    Gates.eq (gate_192.get (1 : Fin 4)) (X.get (1 : Fin 32)) ∧
    Gates.eq (gate_192.get (2 : Fin 4)) (X.get (2 : Fin 32)) ∧
    Gates.eq (gate_192.get (3 : Fin 4)) (X.get (3 : Fin 32)) ∧
    Gates.eq (gate_206.get (0 : Fin 4)) (X.get (4 : Fin 32)) ∧
    Gates.eq (gate_206.get (1 : Fin 4)) (X.get (5 : Fin 32)) ∧
    Gates.eq (gate_206.get (2 : Fin 4)) (X.get (6 : Fin 32)) ∧
    Gates.eq (gate_206.get (3 : Fin 4)) (X.get (7 : Fin 32)) ∧
    Gates.eq (gate_220.get (0 : Fin 4)) (X.get (8 : Fin 32)) ∧
    Gates.eq (gate_220.get (1 : Fin 4)) (X.get (9 : Fin 32)) ∧
    Gates.eq (gate_220.get (2 : Fin 4)) (X.get (10 : Fin 32)) ∧
    Gates.eq (gate_220.get (3 : Fin 4)) (X.get (11 : Fin 32)) ∧
    Gates.eq (gate_234.get (0 : Fin 4)) (X.get (12 : Fin 32)) ∧
    Gates.eq (gate_234.get (1 : Fin 4)) (X.get (13 : Fin 32)) ∧
    Gates.eq (gate_234.get (2 : Fin 4)) (X.get (14 : Fin 32)) ∧
    Gates.eq (gate_234.get (3 : Fin 4)) (X.get (15 : Fin 32)) ∧
    Gates.eq (gate_248.get (0 : Fin 4)) (X.get (16 : Fin 32)) ∧
    Gates.eq (gate_248.get (1 : Fin 4)) (X.get (17 : Fin 32)) ∧
    Gates.eq (gate_248.get (2 : Fin 4)) (X.get (18 : Fin 32)) ∧
    Gates.eq (gate_248.get (3 : Fin 4)) (X.get (19 : Fin 32)) ∧
    Gates.eq (gate_262.get (0 : Fin 4)) (X.get (20 : Fin 32)) ∧
    Gates.eq (gate_262.get (1 : Fin 4)) (X.get (21 : Fin 32)) ∧
    Gates.eq (gate_262.get (2 : Fin 4)) (X.get (22 : Fin 32)) ∧
    Gates.eq (gate_262.get (3 : Fin 4)) (X.get (23 : Fin 32)) ∧
    Gates.eq (gate_276.get (0 : Fin 4)) (X.get (24 : Fin 32)) ∧
    Gates.eq (gate_276.get (1 : Fin 4)) (X.get (25 : Fin 32)) ∧
    Gates.eq (gate_276.get (2 : Fin 4)) (X.get (26 : Fin 32)) ∧
    Gates.eq (gate_276.get (3 : Fin 4)) (X.get (27 : Fin 32)) ∧
    Gates.eq (gate_290.get (0 : Fin 4)) (X.get (28 : Fin 32)) ∧
    Gates.eq (gate_290.get (1 : Fin 4)) (X.get (29 : Fin 32)) ∧
    Gates.eq (gate_290.get (2 : Fin 4)) (X.get (30 : Fin 32)) ∧
    Gates.eq (gate_290.get (3 : Fin 4)) (X.get (31 : Fin 32)) ∧
    True

def DerivePublicKey_32_32 (Sk: List.Vector F 32) (X: List.Vector F 32) (Lo: F) (Hi: F): Prop :=
    RangeCheck 8 (Sk.get (0 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (1 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (2 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (3 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (4 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (5 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (6 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (7 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (8 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (9 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (10 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (11 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (12 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (13 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (14 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (15 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (16 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (17 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (18 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (19 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (20 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (21 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (22 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (23 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (24 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (25 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (26 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (27 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (28 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (29 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (30 : Fin 32)) ∧
    RangeCheck 8 (Sk.get (31 : Fin 32)) ∧
    ∃gate_32, gate_32 = Gates.mul (0:F) (256:F) ∧
    ∃gate_33, gate_33 = Gates.add gate_32 (Sk.get (28 : Fin 32)) ∧
    ∃gate_34, gate_34 = Gates.mul gate_33 (256:F) ∧
    ∃gate_35, gate_35 = Gates.add gate_34 (Sk.get (29 : Fin 32)) ∧
    ∃gate_36, gate_36 = Gates.mul gate_35 (256:F) ∧
    ∃gate_37, gate_37 = Gates.add gate_36 (Sk.get (30 : Fin 32)) ∧
    ∃gate_38, gate_38 = Gates.mul gate_37 (256:F) ∧
    ∃gate_39, gate_39 = Gates.add gate_38 (Sk.get (31 : Fin 32)) ∧
    ∃gate_40, gate_40 = Gates.mul (0:F) (256:F) ∧
    ∃gate_41, gate_41 = Gates.add gate_40 (Sk.get (24 : Fin 32)) ∧
    ∃gate_42, gate_42 = Gates.mul gate_41 (256:F) ∧
    ∃gate_43, gate_43 = Gates.add gate_42 (Sk.get (25 : Fin 32)) ∧
    ∃gate_44, gate_44 = Gates.mul gate_43 (256:F) ∧
    ∃gate_45, gate_45 = Gates.add gate_44 (Sk.get (26 : Fin 32)) ∧
    ∃gate_46, gate_46 = Gates.mul gate_45 (256:F) ∧
    ∃gate_47, gate_47 = Gates.add gate_46 (Sk.get (27 : Fin 32)) ∧
    ∃gate_48, gate_48 = Gates.mul (0:F) (256:F) ∧
    ∃gate_49, gate_49 = Gates.add gate_48 (Sk.get (20 : Fin 32)) ∧
    ∃gate_50, gate_50 = Gates.mul gate_49 (256:F) ∧
    ∃gate_51, gate_51 = Gates.add gate_50 (Sk.get (21 : Fin 32)) ∧
    ∃gate_52, gate_52 = Gates.mul gate_51 (256:F) ∧
    ∃gate_53, gate_53 = Gates.add gate_52 (Sk.get (22 : Fin 32)) ∧
    ∃gate_54, gate_54 = Gates.mul gate_53 (256:F) ∧
    ∃gate_55, gate_55 = Gates.add gate_54 (Sk.get (23 : Fin 32)) ∧
    ∃gate_56, gate_56 = Gates.mul (0:F) (256:F) ∧
    ∃gate_57, gate_57 = Gates.add gate_56 (Sk.get (16 : Fin 32)) ∧
    ∃gate_58, gate_58 = Gates.mul gate_57 (256:F) ∧
    ∃gate_59, gate_59 = Gates.add gate_58 (Sk.get (17 : Fin 32)) ∧
    ∃gate_60, gate_60 = Gates.mul gate_59 (256:F) ∧
    ∃gate_61, gate_61 = Gates.add gate_60 (Sk.get (18 : Fin 32)) ∧
    ∃gate_62, gate_62 = Gates.mul gate_61 (256:F) ∧
    ∃gate_63, gate_63 = Gates.add gate_62 (Sk.get (19 : Fin 32)) ∧
    ∃gate_64, gate_64 = Gates.mul (0:F) (256:F) ∧
    ∃gate_65, gate_65 = Gates.add gate_64 (Sk.get (12 : Fin 32)) ∧
    ∃gate_66, gate_66 = Gates.mul gate_65 (256:F) ∧
    ∃gate_67, gate_67 = Gates.add gate_66 (Sk.get (13 : Fin 32)) ∧
    ∃gate_68, gate_68 = Gates.mul gate_67 (256:F) ∧
    ∃gate_69, gate_69 = Gates.add gate_68 (Sk.get (14 : Fin 32)) ∧
    ∃gate_70, gate_70 = Gates.mul gate_69 (256:F) ∧
    ∃gate_71, gate_71 = Gates.add gate_70 (Sk.get (15 : Fin 32)) ∧
    ∃gate_72, gate_72 = Gates.mul (0:F) (256:F) ∧
    ∃gate_73, gate_73 = Gates.add gate_72 (Sk.get (8 : Fin 32)) ∧
    ∃gate_74, gate_74 = Gates.mul gate_73 (256:F) ∧
    ∃gate_75, gate_75 = Gates.add gate_74 (Sk.get (9 : Fin 32)) ∧
    ∃gate_76, gate_76 = Gates.mul gate_75 (256:F) ∧
    ∃gate_77, gate_77 = Gates.add gate_76 (Sk.get (10 : Fin 32)) ∧
    ∃gate_78, gate_78 = Gates.mul gate_77 (256:F) ∧
    ∃gate_79, gate_79 = Gates.add gate_78 (Sk.get (11 : Fin 32)) ∧
    ∃gate_80, gate_80 = Gates.mul (0:F) (256:F) ∧
    ∃gate_81, gate_81 = Gates.add gate_80 (Sk.get (4 : Fin 32)) ∧
    ∃gate_82, gate_82 = Gates.mul gate_81 (256:F) ∧
    ∃gate_83, gate_83 = Gates.add gate_82 (Sk.get (5 : Fin 32)) ∧
    ∃gate_84, gate_84 = Gates.mul gate_83 (256:F) ∧
    ∃gate_85, gate_85 = Gates.add gate_84 (Sk.get (6 : Fin 32)) ∧
    ∃gate_86, gate_86 = Gates.mul gate_85 (256:F) ∧
    ∃gate_87, gate_87 = Gates.add gate_86 (Sk.get (7 : Fin 32)) ∧
    ∃gate_88, gate_88 = Gates.mul (0:F) (256:F) ∧
    ∃gate_89, gate_89 = Gates.add gate_88 (Sk.get (0 : Fin 32)) ∧
    ∃gate_90, gate_90 = Gates.mul gate_89 (256:F) ∧
    ∃gate_91, gate_91 = Gates.add gate_90 (Sk.get (1 : Fin 32)) ∧
    ∃gate_92, gate_92 = Gates.mul gate_91 (256:F) ∧
    ∃gate_93, gate_93 = Gates.add gate_92 (Sk.get (2 : Fin 32)) ∧
    ∃gate_94, gate_94 = Gates.mul gate_93 (256:F) ∧
    ∃gate_95, gate_95 = Gates.add gate_94 (Sk.get (3 : Fin 32)) ∧
    ∃gate_96 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_96.get (0 : Fin 3)) ∧
    ∃gate_98, gate_98 = Gates.mul (gate_96.get (0 : Fin 3)) (1:F) ∧
    ∃gate_99, gate_99 = Gates.add (0:F) gate_98 ∧
    RangeCheck 11 (gate_96.get (1 : Fin 3)) ∧
    ∃gate_101, gate_101 = Gates.mul (gate_96.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_102, gate_102 = Gates.add gate_99 gate_101 ∧
    RangeCheck 10 (gate_96.get (2 : Fin 3)) ∧
    ∃gate_104, gate_104 = Gates.mul (gate_96.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_105, gate_105 = Gates.add gate_102 gate_104 ∧
    Gates.eq gate_39 gate_105 ∧
    ∃gate_107 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_107.get (0 : Fin 3)) ∧
    ∃gate_109, gate_109 = Gates.mul (gate_107.get (0 : Fin 3)) (1:F) ∧
    ∃gate_110, gate_110 = Gates.add (0:F) gate_109 ∧
    RangeCheck 11 (gate_107.get (1 : Fin 3)) ∧
    ∃gate_112, gate_112 = Gates.mul (gate_107.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_113, gate_113 = Gates.add gate_110 gate_112 ∧
    RangeCheck 10 (gate_107.get (2 : Fin 3)) ∧
    ∃gate_115, gate_115 = Gates.mul (gate_107.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_116, gate_116 = Gates.add gate_113 gate_115 ∧
    Gates.eq gate_47 gate_116 ∧
    ∃gate_118 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_118.get (0 : Fin 3)) ∧
    ∃gate_120, gate_120 = Gates.mul (gate_118.get (0 : Fin 3)) (1:F) ∧
    ∃gate_121, gate_121 = Gates.add (0:F) gate_120 ∧
    RangeCheck 11 (gate_118.get (1 : Fin 3)) ∧
    ∃gate_123, gate_123 = Gates.mul (gate_118.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_124, gate_124 = Gates.add gate_121 gate_123 ∧
    RangeCheck 10 (gate_118.get (2 : Fin 3)) ∧
    ∃gate_126, gate_126 = Gates.mul (gate_118.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_127, gate_127 = Gates.add gate_124 gate_126 ∧
    Gates.eq gate_55 gate_127 ∧
    ∃gate_129 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_129.get (0 : Fin 3)) ∧
    ∃gate_131, gate_131 = Gates.mul (gate_129.get (0 : Fin 3)) (1:F) ∧
    ∃gate_132, gate_132 = Gates.add (0:F) gate_131 ∧
    RangeCheck 11 (gate_129.get (1 : Fin 3)) ∧
    ∃gate_134, gate_134 = Gates.mul (gate_129.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_135, gate_135 = Gates.add gate_132 gate_134 ∧
    RangeCheck 10 (gate_129.get (2 : Fin 3)) ∧
    ∃gate_137, gate_137 = Gates.mul (gate_129.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_138, gate_138 = Gates.add gate_135 gate_137 ∧
    Gates.eq gate_63 gate_138 ∧
    ∃gate_140 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_140.get (0 : Fin 3)) ∧
    ∃gate_142, gate_142 = Gates.mul (gate_140.get (0 : Fin 3)) (1:F) ∧
    ∃gate_143, gate_143 = Gates.add (0:F) gate_142 ∧
    RangeCheck 11 (gate_140.get (1 : Fin 3)) ∧
    ∃gate_145, gate_145 = Gates.mul (gate_140.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_146, gate_146 = Gates.add gate_143 gate_145 ∧
    RangeCheck 10 (gate_140.get (2 : Fin 3)) ∧
    ∃gate_148, gate_148 = Gates.mul (gate_140.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_149, gate_149 = Gates.add gate_146 gate_148 ∧
    Gates.eq gate_71 gate_149 ∧
    ∃gate_151 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_151.get (0 : Fin 3)) ∧
    ∃gate_153, gate_153 = Gates.mul (gate_151.get (0 : Fin 3)) (1:F) ∧
    ∃gate_154, gate_154 = Gates.add (0:F) gate_153 ∧
    RangeCheck 11 (gate_151.get (1 : Fin 3)) ∧
    ∃gate_156, gate_156 = Gates.mul (gate_151.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_157, gate_157 = Gates.add gate_154 gate_156 ∧
    RangeCheck 10 (gate_151.get (2 : Fin 3)) ∧
    ∃gate_159, gate_159 = Gates.mul (gate_151.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_160, gate_160 = Gates.add gate_157 gate_159 ∧
    Gates.eq gate_79 gate_160 ∧
    ∃gate_162 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_162.get (0 : Fin 3)) ∧
    ∃gate_164, gate_164 = Gates.mul (gate_162.get (0 : Fin 3)) (1:F) ∧
    ∃gate_165, gate_165 = Gates.add (0:F) gate_164 ∧
    RangeCheck 11 (gate_162.get (1 : Fin 3)) ∧
    ∃gate_167, gate_167 = Gates.mul (gate_162.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_168, gate_168 = Gates.add gate_165 gate_167 ∧
    RangeCheck 10 (gate_162.get (2 : Fin 3)) ∧
    ∃gate_170, gate_170 = Gates.mul (gate_162.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_171, gate_171 = Gates.add gate_168 gate_170 ∧
    Gates.eq gate_87 gate_171 ∧
    ∃gate_173 : List.Vector F 3, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint
    RangeCheck 11 (gate_173.get (0 : Fin 3)) ∧
    ∃gate_175, gate_175 = Gates.mul (gate_173.get (0 : Fin 3)) (1:F) ∧
    ∃gate_176, gate_176 = Gates.add (0:F) gate_175 ∧
    RangeCheck 11 (gate_173.get (1 : Fin 3)) ∧
    ∃gate_178, gate_178 = Gates.mul (gate_173.get (1 : Fin 3)) (2048:F) ∧
    ∃gate_179, gate_179 = Gates.add gate_176 gate_178 ∧
    RangeCheck 10 (gate_173.get (2 : Fin 3)) ∧
    ∃gate_181, gate_181 = Gates.mul (gate_173.get (2 : Fin 3)) (4194304:F) ∧
    ∃gate_182, gate_182 = Gates.add gate_179 gate_181 ∧
    Gates.eq gate_95 gate_182 ∧
    CheckPolynomial_8_h57d6a69c vec![gate_39, gate_47, gate_55, gate_63, gate_71, gate_79, gate_87, gate_95] fun gate_184 =>
    AssertCanonical_8_1_hcc2f8a19 gate_184 ∧
    ∃gate_186, gate_186 = Gates.add (Gates.add (Gates.add (Gates.add (Gates.add (Gates.add (Gates.add (Gates.add (Gates.add (0:F) (0:F)) (gate_184.get (0 : Fin 8))) (gate_184.get (1 : Fin 8))) (gate_184.get (2 : Fin 8))) (gate_184.get (3 : Fin 8))) (gate_184.get (4 : Fin 8))) (gate_184.get (5 : Fin 8))) (gate_184.get (6 : Fin 8))) (gate_184.get (7 : Fin 8)) ∧
    Gates.ne gate_186 (0:F) ∧
    ScalarMulBase_8_h3037b025 vec![gate_39, gate_47, gate_55, gate_63, gate_71, gate_79, gate_87, gate_95] fun gate_188 =>
    AssertCanonical_8_0_hcc2f8a19 (gate_188.get (0 : Fin 2)) ∧
    AssertCanonical_8_0_hcc2f8a19 (gate_188.get (1 : Fin 2)) ∧
    AssertCanonical_8_0_hcc2f8a19 (gate_188.get (0 : Fin 2)) ∧
    ∃gate_192 : List.Vector F 4, -- hint zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint
    RangeCheck 8 (gate_192.get (0 : Fin 4)) ∧
    RangeCheck 8 (gate_192.get (1 : Fin 4)) ∧
    RangeCheck 8 (gate_192.get (2 : Fin 4)) ∧
    RangeCheck 8 (gate_192.get (3 : Fin 4)) ∧
    ∃gate_197, gate_197 = Gates.mul (0:F) (256:F) ∧
    ∃gate_198, gate_198 = Gates.add gate_197 (gate_192.get (0 : Fin 4)) ∧
    ∃gate_199, gate_199 = Gates.mul gate_198 (256:F) ∧
    DerivePublicKey_32_32_p1 Sk X Lo Hi gate_188 gate_192 gate_199

def AesCtrBlock_32_12_16_16 (Key: List.Vector F 32) (Nonce: List.Vector F 12) (Plaintext: List.Vector F 16) (Ciphertext: List.Vector F 16): Prop :=
    AesKeyExpansion_32 Key fun gate_0 =>
    SpreadByteLookup (Nonce.get (0 : Fin 12)) fun gate_1 =>
    SpreadByteLookup (Nonce.get (1 : Fin 12)) fun gate_2 =>
    SpreadByteLookup (Nonce.get (2 : Fin 12)) fun gate_3 =>
    SpreadByteLookup (Nonce.get (3 : Fin 12)) fun gate_4 =>
    SpreadByteLookup (Nonce.get (4 : Fin 12)) fun gate_5 =>
    SpreadByteLookup (Nonce.get (5 : Fin 12)) fun gate_6 =>
    SpreadByteLookup (Nonce.get (6 : Fin 12)) fun gate_7 =>
    SpreadByteLookup (Nonce.get (7 : Fin 12)) fun gate_8 =>
    SpreadByteLookup (Nonce.get (8 : Fin 12)) fun gate_9 =>
    SpreadByteLookup (Nonce.get (9 : Fin 12)) fun gate_10 =>
    SpreadByteLookup (Nonce.get (10 : Fin 12)) fun gate_11 =>
    SpreadByteLookup (Nonce.get (11 : Fin 12)) fun gate_12 =>
    ∃gate_13, gate_13 = Gates.add gate_1 ((gate_0.get (0 : Fin 2)).get (0 : Fin 240)) ∧
    ∃gate_14, gate_14 = Gates.add gate_2 ((gate_0.get (0 : Fin 2)).get (1 : Fin 240)) ∧
    ∃gate_15, gate_15 = Gates.add gate_3 ((gate_0.get (0 : Fin 2)).get (2 : Fin 240)) ∧
    ∃gate_16, gate_16 = Gates.add gate_4 ((gate_0.get (0 : Fin 2)).get (3 : Fin 240)) ∧
    ∃gate_17, gate_17 = Gates.add gate_5 ((gate_0.get (0 : Fin 2)).get (4 : Fin 240)) ∧
    ∃gate_18, gate_18 = Gates.add gate_6 ((gate_0.get (0 : Fin 2)).get (5 : Fin 240)) ∧
    ∃gate_19, gate_19 = Gates.add gate_7 ((gate_0.get (0 : Fin 2)).get (6 : Fin 240)) ∧
    ∃gate_20, gate_20 = Gates.add gate_8 ((gate_0.get (0 : Fin 2)).get (7 : Fin 240)) ∧
    ∃gate_21, gate_21 = Gates.add gate_9 ((gate_0.get (0 : Fin 2)).get (8 : Fin 240)) ∧
    ∃gate_22, gate_22 = Gates.add gate_10 ((gate_0.get (0 : Fin 2)).get (9 : Fin 240)) ∧
    ∃gate_23, gate_23 = Gates.add gate_11 ((gate_0.get (0 : Fin 2)).get (10 : Fin 240)) ∧
    ∃gate_24, gate_24 = Gates.add gate_12 ((gate_0.get (0 : Fin 2)).get (11 : Fin 240)) ∧
    ∃gate_25, gate_25 = Gates.mul gate_13 (1:F) ∧
    ∃gate_26, gate_26 = Gates.add (0:F) gate_25 ∧
    ∃gate_27, gate_27 = Gates.mul gate_14 (1679616:F) ∧
    ∃gate_28, gate_28 = Gates.add gate_26 gate_27 ∧
    ∃gate_29, gate_29 = Gates.mul gate_15 (2821109907456:F) ∧
    ∃gate_30, gate_30 = Gates.add gate_28 gate_29 ∧
    ∃gate_31, gate_31 = Gates.mul gate_16 (4738381338321616896:F) ∧
    ∃gate_32, gate_32 = Gates.add gate_30 gate_31 ∧
    AesDecodeWord_4 gate_32 fun gate_33 =>
    ∃gate_34, gate_34 = Gates.mul gate_17 (1:F) ∧
    ∃gate_35, gate_35 = Gates.add (0:F) gate_34 ∧
    ∃gate_36, gate_36 = Gates.mul gate_18 (1679616:F) ∧
    ∃gate_37, gate_37 = Gates.add gate_35 gate_36 ∧
    ∃gate_38, gate_38 = Gates.mul gate_19 (2821109907456:F) ∧
    ∃gate_39, gate_39 = Gates.add gate_37 gate_38 ∧
    ∃gate_40, gate_40 = Gates.mul gate_20 (4738381338321616896:F) ∧
    ∃gate_41, gate_41 = Gates.add gate_39 gate_40 ∧
    AesDecodeWord_4 gate_41 fun gate_42 =>
    ∃gate_43, gate_43 = Gates.mul gate_21 (1:F) ∧
    ∃gate_44, gate_44 = Gates.add (0:F) gate_43 ∧
    ∃gate_45, gate_45 = Gates.mul gate_22 (1679616:F) ∧
    ∃gate_46, gate_46 = Gates.add gate_44 gate_45 ∧
    ∃gate_47, gate_47 = Gates.mul gate_23 (2821109907456:F) ∧
    ∃gate_48, gate_48 = Gates.add gate_46 gate_47 ∧
    ∃gate_49, gate_49 = Gates.mul gate_24 (4738381338321616896:F) ∧
    ∃gate_50, gate_50 = Gates.add gate_48 gate_49 ∧
    AesDecodeWord_4 gate_50 fun gate_51 =>
    SpreadByteLookup (Plaintext.get (0 : Fin 16)) fun gate_52 =>
    SpreadByteLookup (Plaintext.get (1 : Fin 16)) fun gate_53 =>
    SpreadByteLookup (Plaintext.get (2 : Fin 16)) fun gate_54 =>
    SpreadByteLookup (Plaintext.get (3 : Fin 16)) fun gate_55 =>
    SpreadByteLookup (Plaintext.get (4 : Fin 16)) fun gate_56 =>
    SpreadByteLookup (Plaintext.get (5 : Fin 16)) fun gate_57 =>
    SpreadByteLookup (Plaintext.get (6 : Fin 16)) fun gate_58 =>
    SpreadByteLookup (Plaintext.get (7 : Fin 16)) fun gate_59 =>
    SpreadByteLookup (Plaintext.get (8 : Fin 16)) fun gate_60 =>
    SpreadByteLookup (Plaintext.get (9 : Fin 16)) fun gate_61 =>
    SpreadByteLookup (Plaintext.get (10 : Fin 16)) fun gate_62 =>
    SpreadByteLookup (Plaintext.get (11 : Fin 16)) fun gate_63 =>
    SpreadByteLookup (Plaintext.get (12 : Fin 16)) fun gate_64 =>
    SpreadByteLookup (Plaintext.get (13 : Fin 16)) fun gate_65 =>
    SpreadByteLookup (Plaintext.get (14 : Fin 16)) fun gate_66 =>
    SpreadByteLookup (Plaintext.get (15 : Fin 16)) fun gate_67 =>
    AesRoundColumn_4_4 vec![(gate_42.get (0 : Fin 4)), (gate_51.get (1 : Fin 4)), ((gate_0.get (1 : Fin 2)).get (14 : Fin 240)), (gate_33.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (20 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (21 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (22 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (23 : Fin 240))] fun gate_68 =>
    AesRoundColumn_4_4 vec![(gate_51.get (0 : Fin 4)), ((gate_0.get (1 : Fin 2)).get (13 : Fin 240)), (gate_33.get (2 : Fin 4)), (gate_42.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (24 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (25 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (26 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (27 : Fin 240))] fun gate_69 =>
    AesRoundColumn_4_4 vec![((gate_0.get (1 : Fin 2)).get (12 : Fin 240)), (gate_33.get (1 : Fin 4)), (gate_42.get (2 : Fin 4)), (gate_51.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (28 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (29 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (30 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (31 : Fin 240))] fun gate_70 =>
    ∃gate_71, gate_71 = Gates.mul ((gate_0.get (0 : Fin 2)).get (16 : Fin 240)) (1:F) ∧
    ∃gate_72, gate_72 = Gates.add (0:F) gate_71 ∧
    ∃gate_73, gate_73 = Gates.mul ((gate_0.get (0 : Fin 2)).get (17 : Fin 240)) (1679616:F) ∧
    ∃gate_74, gate_74 = Gates.add gate_72 gate_73 ∧
    ∃gate_75, gate_75 = Gates.mul ((gate_0.get (0 : Fin 2)).get (18 : Fin 240)) (2821109907456:F) ∧
    ∃gate_76, gate_76 = Gates.add gate_74 gate_75 ∧
    ∃gate_77, gate_77 = Gates.mul ((gate_0.get (0 : Fin 2)).get (19 : Fin 240)) (4738381338321616896:F) ∧
    ∃gate_78, gate_78 = Gates.add gate_76 gate_77 ∧
    ∃gate_79, gate_79 = Gates.add (gate_33.get (0 : Fin 4)) (0:F) ∧
    SubstitutionLookup gate_79 fun gate_80 =>
    ∃gate_81, gate_81 = Gates.add gate_78 gate_80 ∧
    ∃gate_82, gate_82 = Gates.add (gate_42.get (1 : Fin 4)) (256:F) ∧
    SubstitutionLookup gate_82 fun gate_83 =>
    ∃gate_84, gate_84 = Gates.add gate_81 gate_83 ∧
    ∃gate_85, gate_85 = Gates.add (gate_51.get (2 : Fin 4)) (512:F) ∧
    SubstitutionLookup gate_85 fun gate_86 =>
    ∃gate_87, gate_87 = Gates.add gate_84 gate_86 ∧
    AesCounterByte_2 ((gate_0.get (0 : Fin 2)).get (15 : Fin 240)) fun gate_88 =>
    ∃gate_89, gate_89 = Gates.add gate_88 (768:F) ∧
    SubstitutionLookup gate_89 fun gate_90 =>
    ∃gate_91, gate_91 = Gates.add gate_87 gate_90 ∧
    AesDecodeWord_4 gate_91 fun gate_92 =>
    AesRoundColumn_4_4 vec![(gate_92.get (0 : Fin 4)), (gate_68.get (1 : Fin 4)), (gate_69.get (2 : Fin 4)), (gate_70.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (32 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (33 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (34 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (35 : Fin 240))] fun gate_93 =>
    AesRoundColumn_4_4 vec![(gate_68.get (0 : Fin 4)), (gate_69.get (1 : Fin 4)), (gate_70.get (2 : Fin 4)), (gate_92.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (36 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (37 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (38 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (39 : Fin 240))] fun gate_94 =>
    AesRoundColumn_4_4 vec![(gate_69.get (0 : Fin 4)), (gate_70.get (1 : Fin 4)), (gate_92.get (2 : Fin 4)), (gate_68.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (40 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (41 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (42 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (43 : Fin 240))] fun gate_95 =>
    AesRoundColumn_4_4 vec![(gate_70.get (0 : Fin 4)), (gate_92.get (1 : Fin 4)), (gate_68.get (2 : Fin 4)), (gate_69.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (44 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (45 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (46 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (47 : Fin 240))] fun gate_96 =>
    AesRoundColumn_4_4 vec![(gate_93.get (0 : Fin 4)), (gate_94.get (1 : Fin 4)), (gate_95.get (2 : Fin 4)), (gate_96.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (48 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (49 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (50 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (51 : Fin 240))] fun gate_97 =>
    AesRoundColumn_4_4 vec![(gate_94.get (0 : Fin 4)), (gate_95.get (1 : Fin 4)), (gate_96.get (2 : Fin 4)), (gate_93.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (52 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (53 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (54 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (55 : Fin 240))] fun gate_98 =>
    AesRoundColumn_4_4 vec![(gate_95.get (0 : Fin 4)), (gate_96.get (1 : Fin 4)), (gate_93.get (2 : Fin 4)), (gate_94.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (56 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (57 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (58 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (59 : Fin 240))] fun gate_99 =>
    AesRoundColumn_4_4 vec![(gate_96.get (0 : Fin 4)), (gate_93.get (1 : Fin 4)), (gate_94.get (2 : Fin 4)), (gate_95.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (60 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (61 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (62 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (63 : Fin 240))] fun gate_100 =>
    AesRoundColumn_4_4 vec![(gate_97.get (0 : Fin 4)), (gate_98.get (1 : Fin 4)), (gate_99.get (2 : Fin 4)), (gate_100.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (64 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (65 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (66 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (67 : Fin 240))] fun gate_101 =>
    AesRoundColumn_4_4 vec![(gate_98.get (0 : Fin 4)), (gate_99.get (1 : Fin 4)), (gate_100.get (2 : Fin 4)), (gate_97.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (68 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (69 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (70 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (71 : Fin 240))] fun gate_102 =>
    AesRoundColumn_4_4 vec![(gate_99.get (0 : Fin 4)), (gate_100.get (1 : Fin 4)), (gate_97.get (2 : Fin 4)), (gate_98.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (72 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (73 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (74 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (75 : Fin 240))] fun gate_103 =>
    AesRoundColumn_4_4 vec![(gate_100.get (0 : Fin 4)), (gate_97.get (1 : Fin 4)), (gate_98.get (2 : Fin 4)), (gate_99.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (76 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (77 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (78 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (79 : Fin 240))] fun gate_104 =>
    AesRoundColumn_4_4 vec![(gate_101.get (0 : Fin 4)), (gate_102.get (1 : Fin 4)), (gate_103.get (2 : Fin 4)), (gate_104.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (80 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (81 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (82 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (83 : Fin 240))] fun gate_105 =>
    AesRoundColumn_4_4 vec![(gate_102.get (0 : Fin 4)), (gate_103.get (1 : Fin 4)), (gate_104.get (2 : Fin 4)), (gate_101.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (84 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (85 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (86 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (87 : Fin 240))] fun gate_106 =>
    AesRoundColumn_4_4 vec![(gate_103.get (0 : Fin 4)), (gate_104.get (1 : Fin 4)), (gate_101.get (2 : Fin 4)), (gate_102.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (88 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (89 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (90 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (91 : Fin 240))] fun gate_107 =>
    AesRoundColumn_4_4 vec![(gate_104.get (0 : Fin 4)), (gate_101.get (1 : Fin 4)), (gate_102.get (2 : Fin 4)), (gate_103.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (92 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (93 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (94 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (95 : Fin 240))] fun gate_108 =>
    AesRoundColumn_4_4 vec![(gate_105.get (0 : Fin 4)), (gate_106.get (1 : Fin 4)), (gate_107.get (2 : Fin 4)), (gate_108.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (96 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (97 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (98 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (99 : Fin 240))] fun gate_109 =>
    AesRoundColumn_4_4 vec![(gate_106.get (0 : Fin 4)), (gate_107.get (1 : Fin 4)), (gate_108.get (2 : Fin 4)), (gate_105.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (100 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (101 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (102 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (103 : Fin 240))] fun gate_110 =>
    AesRoundColumn_4_4 vec![(gate_107.get (0 : Fin 4)), (gate_108.get (1 : Fin 4)), (gate_105.get (2 : Fin 4)), (gate_106.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (104 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (105 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (106 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (107 : Fin 240))] fun gate_111 =>
    AesRoundColumn_4_4 vec![(gate_108.get (0 : Fin 4)), (gate_105.get (1 : Fin 4)), (gate_106.get (2 : Fin 4)), (gate_107.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (108 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (109 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (110 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (111 : Fin 240))] fun gate_112 =>
    AesRoundColumn_4_4 vec![(gate_109.get (0 : Fin 4)), (gate_110.get (1 : Fin 4)), (gate_111.get (2 : Fin 4)), (gate_112.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (112 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (113 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (114 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (115 : Fin 240))] fun gate_113 =>
    AesRoundColumn_4_4 vec![(gate_110.get (0 : Fin 4)), (gate_111.get (1 : Fin 4)), (gate_112.get (2 : Fin 4)), (gate_109.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (116 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (117 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (118 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (119 : Fin 240))] fun gate_114 =>
    AesRoundColumn_4_4 vec![(gate_111.get (0 : Fin 4)), (gate_112.get (1 : Fin 4)), (gate_109.get (2 : Fin 4)), (gate_110.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (120 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (121 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (122 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (123 : Fin 240))] fun gate_115 =>
    AesRoundColumn_4_4 vec![(gate_112.get (0 : Fin 4)), (gate_109.get (1 : Fin 4)), (gate_110.get (2 : Fin 4)), (gate_111.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (124 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (125 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (126 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (127 : Fin 240))] fun gate_116 =>
    AesRoundColumn_4_4 vec![(gate_113.get (0 : Fin 4)), (gate_114.get (1 : Fin 4)), (gate_115.get (2 : Fin 4)), (gate_116.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (128 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (129 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (130 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (131 : Fin 240))] fun gate_117 =>
    AesRoundColumn_4_4 vec![(gate_114.get (0 : Fin 4)), (gate_115.get (1 : Fin 4)), (gate_116.get (2 : Fin 4)), (gate_113.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (132 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (133 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (134 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (135 : Fin 240))] fun gate_118 =>
    AesRoundColumn_4_4 vec![(gate_115.get (0 : Fin 4)), (gate_116.get (1 : Fin 4)), (gate_113.get (2 : Fin 4)), (gate_114.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (136 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (137 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (138 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (139 : Fin 240))] fun gate_119 =>
    AesRoundColumn_4_4 vec![(gate_116.get (0 : Fin 4)), (gate_113.get (1 : Fin 4)), (gate_114.get (2 : Fin 4)), (gate_115.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (140 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (141 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (142 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (143 : Fin 240))] fun gate_120 =>
    AesRoundColumn_4_4 vec![(gate_117.get (0 : Fin 4)), (gate_118.get (1 : Fin 4)), (gate_119.get (2 : Fin 4)), (gate_120.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (144 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (145 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (146 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (147 : Fin 240))] fun gate_121 =>
    AesRoundColumn_4_4 vec![(gate_118.get (0 : Fin 4)), (gate_119.get (1 : Fin 4)), (gate_120.get (2 : Fin 4)), (gate_117.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (148 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (149 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (150 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (151 : Fin 240))] fun gate_122 =>
    AesRoundColumn_4_4 vec![(gate_119.get (0 : Fin 4)), (gate_120.get (1 : Fin 4)), (gate_117.get (2 : Fin 4)), (gate_118.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (152 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (153 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (154 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (155 : Fin 240))] fun gate_123 =>
    AesRoundColumn_4_4 vec![(gate_120.get (0 : Fin 4)), (gate_117.get (1 : Fin 4)), (gate_118.get (2 : Fin 4)), (gate_119.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (156 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (157 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (158 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (159 : Fin 240))] fun gate_124 =>
    AesRoundColumn_4_4 vec![(gate_121.get (0 : Fin 4)), (gate_122.get (1 : Fin 4)), (gate_123.get (2 : Fin 4)), (gate_124.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (160 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (161 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (162 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (163 : Fin 240))] fun gate_125 =>
    AesRoundColumn_4_4 vec![(gate_122.get (0 : Fin 4)), (gate_123.get (1 : Fin 4)), (gate_124.get (2 : Fin 4)), (gate_121.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (164 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (165 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (166 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (167 : Fin 240))] fun gate_126 =>
    AesRoundColumn_4_4 vec![(gate_123.get (0 : Fin 4)), (gate_124.get (1 : Fin 4)), (gate_121.get (2 : Fin 4)), (gate_122.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (168 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (169 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (170 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (171 : Fin 240))] fun gate_127 =>
    AesRoundColumn_4_4 vec![(gate_124.get (0 : Fin 4)), (gate_121.get (1 : Fin 4)), (gate_122.get (2 : Fin 4)), (gate_123.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (172 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (173 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (174 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (175 : Fin 240))] fun gate_128 =>
    AesRoundColumn_4_4 vec![(gate_125.get (0 : Fin 4)), (gate_126.get (1 : Fin 4)), (gate_127.get (2 : Fin 4)), (gate_128.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (176 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (177 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (178 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (179 : Fin 240))] fun gate_129 =>
    AesRoundColumn_4_4 vec![(gate_126.get (0 : Fin 4)), (gate_127.get (1 : Fin 4)), (gate_128.get (2 : Fin 4)), (gate_125.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (180 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (181 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (182 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (183 : Fin 240))] fun gate_130 =>
    AesRoundColumn_4_4 vec![(gate_127.get (0 : Fin 4)), (gate_128.get (1 : Fin 4)), (gate_125.get (2 : Fin 4)), (gate_126.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (184 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (185 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (186 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (187 : Fin 240))] fun gate_131 =>
    AesRoundColumn_4_4 vec![(gate_128.get (0 : Fin 4)), (gate_125.get (1 : Fin 4)), (gate_126.get (2 : Fin 4)), (gate_127.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (188 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (189 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (190 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (191 : Fin 240))] fun gate_132 =>
    AesRoundColumn_4_4 vec![(gate_129.get (0 : Fin 4)), (gate_130.get (1 : Fin 4)), (gate_131.get (2 : Fin 4)), (gate_132.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (192 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (193 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (194 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (195 : Fin 240))] fun gate_133 =>
    AesRoundColumn_4_4 vec![(gate_130.get (0 : Fin 4)), (gate_131.get (1 : Fin 4)), (gate_132.get (2 : Fin 4)), (gate_129.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (196 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (197 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (198 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (199 : Fin 240))] fun gate_134 =>
    AesRoundColumn_4_4 vec![(gate_131.get (0 : Fin 4)), (gate_132.get (1 : Fin 4)), (gate_129.get (2 : Fin 4)), (gate_130.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (200 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (201 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (202 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (203 : Fin 240))] fun gate_135 =>
    AesRoundColumn_4_4 vec![(gate_132.get (0 : Fin 4)), (gate_129.get (1 : Fin 4)), (gate_130.get (2 : Fin 4)), (gate_131.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (204 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (205 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (206 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (207 : Fin 240))] fun gate_136 =>
    AesRoundColumn_4_4 vec![(gate_133.get (0 : Fin 4)), (gate_134.get (1 : Fin 4)), (gate_135.get (2 : Fin 4)), (gate_136.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (208 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (209 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (210 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (211 : Fin 240))] fun gate_137 =>
    AesRoundColumn_4_4 vec![(gate_134.get (0 : Fin 4)), (gate_135.get (1 : Fin 4)), (gate_136.get (2 : Fin 4)), (gate_133.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (212 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (213 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (214 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (215 : Fin 240))] fun gate_138 =>
    AesRoundColumn_4_4 vec![(gate_135.get (0 : Fin 4)), (gate_136.get (1 : Fin 4)), (gate_133.get (2 : Fin 4)), (gate_134.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (216 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (217 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (218 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (219 : Fin 240))] fun gate_139 =>
    AesRoundColumn_4_4 vec![(gate_136.get (0 : Fin 4)), (gate_133.get (1 : Fin 4)), (gate_134.get (2 : Fin 4)), (gate_135.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (220 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (221 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (222 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (223 : Fin 240))] fun gate_140 =>
    AesFinalRound_16_16_16 vec![(gate_137.get (0 : Fin 4)), (gate_137.get (1 : Fin 4)), (gate_137.get (2 : Fin 4)), (gate_137.get (3 : Fin 4)), (gate_138.get (0 : Fin 4)), (gate_138.get (1 : Fin 4)), (gate_138.get (2 : Fin 4)), (gate_138.get (3 : Fin 4)), (gate_139.get (0 : Fin 4)), (gate_139.get (1 : Fin 4)), (gate_139.get (2 : Fin 4)), (gate_139.get (3 : Fin 4)), (gate_140.get (0 : Fin 4)), (gate_140.get (1 : Fin 4)), (gate_140.get (2 : Fin 4)), (gate_140.get (3 : Fin 4))] vec![((gate_0.get (0 : Fin 2)).get (224 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (225 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (226 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (227 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (228 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (229 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (230 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (231 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (232 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (233 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (234 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (235 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (236 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (237 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (238 : Fin 240)), ((gate_0.get (0 : Fin 2)).get (239 : Fin 240))] vec![gate_52, gate_53, gate_54, gate_55, gate_56, gate_57, gate_58, gate_59, gate_60, gate_61, gate_62, gate_63, gate_64, gate_65, gate_66, gate_67] fun gate_141 =>
    Gates.eq (gate_141.get (0 : Fin 16)) (Ciphertext.get (0 : Fin 16)) ∧
    Gates.eq (gate_141.get (1 : Fin 16)) (Ciphertext.get (1 : Fin 16)) ∧
    Gates.eq (gate_141.get (2 : Fin 16)) (Ciphertext.get (2 : Fin 16)) ∧
    Gates.eq (gate_141.get (3 : Fin 16)) (Ciphertext.get (3 : Fin 16)) ∧
    Gates.eq (gate_141.get (4 : Fin 16)) (Ciphertext.get (4 : Fin 16)) ∧
    Gates.eq (gate_141.get (5 : Fin 16)) (Ciphertext.get (5 : Fin 16)) ∧
    Gates.eq (gate_141.get (6 : Fin 16)) (Ciphertext.get (6 : Fin 16)) ∧
    Gates.eq (gate_141.get (7 : Fin 16)) (Ciphertext.get (7 : Fin 16)) ∧
    Gates.eq (gate_141.get (8 : Fin 16)) (Ciphertext.get (8 : Fin 16)) ∧
    Gates.eq (gate_141.get (9 : Fin 16)) (Ciphertext.get (9 : Fin 16)) ∧
    Gates.eq (gate_141.get (10 : Fin 16)) (Ciphertext.get (10 : Fin 16)) ∧
    Gates.eq (gate_141.get (11 : Fin 16)) (Ciphertext.get (11 : Fin 16)) ∧
    Gates.eq (gate_141.get (12 : Fin 16)) (Ciphertext.get (12 : Fin 16)) ∧
    Gates.eq (gate_141.get (13 : Fin 16)) (Ciphertext.get (13 : Fin 16)) ∧
    Gates.eq (gate_141.get (14 : Fin 16)) (Ciphertext.get (14 : Fin 16)) ∧
    Gates.eq (gate_141.get (15 : Fin 16)) (Ciphertext.get (15 : Fin 16)) ∧
    True

def KeySchedule_32_12 (SharedSecret: F) (Key: List.Vector F 32) (Nonce: List.Vector F 12): Prop :=
    ∃gate_0, gate_0 = Gates.mul (0:F) (256:F) ∧
    ∃gate_1, gate_1 = Gates.add gate_0 (84:F) ∧
    ∃gate_2, gate_2 = Gates.mul gate_1 (256:F) ∧
    ∃gate_3, gate_3 = Gates.add gate_2 (77:F) ∧
    ∃gate_4, gate_4 = Gates.mul gate_3 (256:F) ∧
    ∃gate_5, gate_5 = Gates.add gate_4 (69:F) ∧
    ∃gate_6, gate_6 = Gates.mul gate_5 (256:F) ∧
    ∃gate_7, gate_7 = Gates.add gate_6 (67:F) ∧
    Poseidon_3 vec![(1414353737:F), SharedSecret, gate_7] (0:F) fun gate_8 =>
    Poseidon_2 vec![(1414353739:F), gate_8] (0:F) fun gate_9 =>
    Poseidon_2 vec![(1414353740:F), gate_8] (0:F) fun gate_10 =>
    FieldBytesBE_32 gate_9 fun gate_11 =>
    FieldBytesBE_32 gate_10 fun gate_12 =>
    Poseidon_2 vec![(1414353742:F), gate_8] (0:F) fun gate_13 =>
    FieldBytesBE_32 gate_13 fun gate_14 =>
    Gates.eq (gate_12.get (16 : Fin 32)) (Key.get (0 : Fin 32)) ∧
    Gates.eq (gate_12.get (17 : Fin 32)) (Key.get (1 : Fin 32)) ∧
    Gates.eq (gate_12.get (18 : Fin 32)) (Key.get (2 : Fin 32)) ∧
    Gates.eq (gate_12.get (19 : Fin 32)) (Key.get (3 : Fin 32)) ∧
    Gates.eq (gate_12.get (20 : Fin 32)) (Key.get (4 : Fin 32)) ∧
    Gates.eq (gate_12.get (21 : Fin 32)) (Key.get (5 : Fin 32)) ∧
    Gates.eq (gate_12.get (22 : Fin 32)) (Key.get (6 : Fin 32)) ∧
    Gates.eq (gate_12.get (23 : Fin 32)) (Key.get (7 : Fin 32)) ∧
    Gates.eq (gate_12.get (24 : Fin 32)) (Key.get (8 : Fin 32)) ∧
    Gates.eq (gate_12.get (25 : Fin 32)) (Key.get (9 : Fin 32)) ∧
    Gates.eq (gate_12.get (26 : Fin 32)) (Key.get (10 : Fin 32)) ∧
    Gates.eq (gate_12.get (27 : Fin 32)) (Key.get (11 : Fin 32)) ∧
    Gates.eq (gate_12.get (28 : Fin 32)) (Key.get (12 : Fin 32)) ∧
    Gates.eq (gate_12.get (29 : Fin 32)) (Key.get (13 : Fin 32)) ∧
    Gates.eq (gate_12.get (30 : Fin 32)) (Key.get (14 : Fin 32)) ∧
    Gates.eq (gate_12.get (31 : Fin 32)) (Key.get (15 : Fin 32)) ∧
    Gates.eq (gate_11.get (16 : Fin 32)) (Key.get (16 : Fin 32)) ∧
    Gates.eq (gate_11.get (17 : Fin 32)) (Key.get (17 : Fin 32)) ∧
    Gates.eq (gate_11.get (18 : Fin 32)) (Key.get (18 : Fin 32)) ∧
    Gates.eq (gate_11.get (19 : Fin 32)) (Key.get (19 : Fin 32)) ∧
    Gates.eq (gate_11.get (20 : Fin 32)) (Key.get (20 : Fin 32)) ∧
    Gates.eq (gate_11.get (21 : Fin 32)) (Key.get (21 : Fin 32)) ∧
    Gates.eq (gate_11.get (22 : Fin 32)) (Key.get (22 : Fin 32)) ∧
    Gates.eq (gate_11.get (23 : Fin 32)) (Key.get (23 : Fin 32)) ∧
    Gates.eq (gate_11.get (24 : Fin 32)) (Key.get (24 : Fin 32)) ∧
    Gates.eq (gate_11.get (25 : Fin 32)) (Key.get (25 : Fin 32)) ∧
    Gates.eq (gate_11.get (26 : Fin 32)) (Key.get (26 : Fin 32)) ∧
    Gates.eq (gate_11.get (27 : Fin 32)) (Key.get (27 : Fin 32)) ∧
    Gates.eq (gate_11.get (28 : Fin 32)) (Key.get (28 : Fin 32)) ∧
    Gates.eq (gate_11.get (29 : Fin 32)) (Key.get (29 : Fin 32)) ∧
    Gates.eq (gate_11.get (30 : Fin 32)) (Key.get (30 : Fin 32)) ∧
    Gates.eq (gate_11.get (31 : Fin 32)) (Key.get (31 : Fin 32)) ∧
    Gates.eq (gate_14.get (20 : Fin 32)) (Nonce.get (0 : Fin 12)) ∧
    Gates.eq (gate_14.get (21 : Fin 32)) (Nonce.get (1 : Fin 12)) ∧
    Gates.eq (gate_14.get (22 : Fin 32)) (Nonce.get (2 : Fin 12)) ∧
    Gates.eq (gate_14.get (23 : Fin 32)) (Nonce.get (3 : Fin 12)) ∧
    Gates.eq (gate_14.get (24 : Fin 32)) (Nonce.get (4 : Fin 12)) ∧
    Gates.eq (gate_14.get (25 : Fin 32)) (Nonce.get (5 : Fin 12)) ∧
    Gates.eq (gate_14.get (26 : Fin 32)) (Nonce.get (6 : Fin 12)) ∧
    Gates.eq (gate_14.get (27 : Fin 32)) (Nonce.get (7 : Fin 12)) ∧
    Gates.eq (gate_14.get (28 : Fin 32)) (Nonce.get (8 : Fin 12)) ∧
    Gates.eq (gate_14.get (29 : Fin 32)) (Nonce.get (9 : Fin 12)) ∧
    Gates.eq (gate_14.get (30 : Fin 32)) (Nonce.get (10 : Fin 12)) ∧
    Gates.eq (gate_14.get (31 : Fin 32)) (Nonce.get (11 : Fin 12)) ∧
    True

def Envelope_32_65_16_16_p2 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Plaintext: List.Vector F 16) (RecipientLo: F) (RecipientHi: F) (EphemeralLo: F) (EphemeralHi: F) (Ciphertext: List.Vector F 16) (gate_259: F) (gate_263: F) (gate_364: List.Vector F 2) (gate_396: List.Vector F 32) (gate_397: List.Vector (List.Vector F 240) 2) (gate_398: F) (gate_399: F): Prop :=
    SpreadByteLookup (gate_396.get (22 : Fin 32)) fun gate_400 =>
    SpreadByteLookup (gate_396.get (23 : Fin 32)) fun gate_401 =>
    SpreadByteLookup (gate_396.get (24 : Fin 32)) fun gate_402 =>
    SpreadByteLookup (gate_396.get (25 : Fin 32)) fun gate_403 =>
    SpreadByteLookup (gate_396.get (26 : Fin 32)) fun gate_404 =>
    SpreadByteLookup (gate_396.get (27 : Fin 32)) fun gate_405 =>
    SpreadByteLookup (gate_396.get (28 : Fin 32)) fun gate_406 =>
    SpreadByteLookup (gate_396.get (29 : Fin 32)) fun gate_407 =>
    SpreadByteLookup (gate_396.get (30 : Fin 32)) fun gate_408 =>
    SpreadByteLookup (gate_396.get (31 : Fin 32)) fun gate_409 =>
    ∃gate_410, gate_410 = Gates.add gate_398 ((gate_397.get (0 : Fin 2)).get (0 : Fin 240)) ∧
    ∃gate_411, gate_411 = Gates.add gate_399 ((gate_397.get (0 : Fin 2)).get (1 : Fin 240)) ∧
    ∃gate_412, gate_412 = Gates.add gate_400 ((gate_397.get (0 : Fin 2)).get (2 : Fin 240)) ∧
    ∃gate_413, gate_413 = Gates.add gate_401 ((gate_397.get (0 : Fin 2)).get (3 : Fin 240)) ∧
    ∃gate_414, gate_414 = Gates.add gate_402 ((gate_397.get (0 : Fin 2)).get (4 : Fin 240)) ∧
    ∃gate_415, gate_415 = Gates.add gate_403 ((gate_397.get (0 : Fin 2)).get (5 : Fin 240)) ∧
    ∃gate_416, gate_416 = Gates.add gate_404 ((gate_397.get (0 : Fin 2)).get (6 : Fin 240)) ∧
    ∃gate_417, gate_417 = Gates.add gate_405 ((gate_397.get (0 : Fin 2)).get (7 : Fin 240)) ∧
    ∃gate_418, gate_418 = Gates.add gate_406 ((gate_397.get (0 : Fin 2)).get (8 : Fin 240)) ∧
    ∃gate_419, gate_419 = Gates.add gate_407 ((gate_397.get (0 : Fin 2)).get (9 : Fin 240)) ∧
    ∃gate_420, gate_420 = Gates.add gate_408 ((gate_397.get (0 : Fin 2)).get (10 : Fin 240)) ∧
    ∃gate_421, gate_421 = Gates.add gate_409 ((gate_397.get (0 : Fin 2)).get (11 : Fin 240)) ∧
    ∃gate_422, gate_422 = Gates.mul gate_410 (1:F) ∧
    ∃gate_423, gate_423 = Gates.add (0:F) gate_422 ∧
    ∃gate_424, gate_424 = Gates.mul gate_411 (1679616:F) ∧
    ∃gate_425, gate_425 = Gates.add gate_423 gate_424 ∧
    ∃gate_426, gate_426 = Gates.mul gate_412 (2821109907456:F) ∧
    ∃gate_427, gate_427 = Gates.add gate_425 gate_426 ∧
    ∃gate_428, gate_428 = Gates.mul gate_413 (4738381338321616896:F) ∧
    ∃gate_429, gate_429 = Gates.add gate_427 gate_428 ∧
    AesDecodeWord_4 gate_429 fun gate_430 =>
    ∃gate_431, gate_431 = Gates.mul gate_414 (1:F) ∧
    ∃gate_432, gate_432 = Gates.add (0:F) gate_431 ∧
    ∃gate_433, gate_433 = Gates.mul gate_415 (1679616:F) ∧
    ∃gate_434, gate_434 = Gates.add gate_432 gate_433 ∧
    ∃gate_435, gate_435 = Gates.mul gate_416 (2821109907456:F) ∧
    ∃gate_436, gate_436 = Gates.add gate_434 gate_435 ∧
    ∃gate_437, gate_437 = Gates.mul gate_417 (4738381338321616896:F) ∧
    ∃gate_438, gate_438 = Gates.add gate_436 gate_437 ∧
    AesDecodeWord_4 gate_438 fun gate_439 =>
    ∃gate_440, gate_440 = Gates.mul gate_418 (1:F) ∧
    ∃gate_441, gate_441 = Gates.add (0:F) gate_440 ∧
    ∃gate_442, gate_442 = Gates.mul gate_419 (1679616:F) ∧
    ∃gate_443, gate_443 = Gates.add gate_441 gate_442 ∧
    ∃gate_444, gate_444 = Gates.mul gate_420 (2821109907456:F) ∧
    ∃gate_445, gate_445 = Gates.add gate_443 gate_444 ∧
    ∃gate_446, gate_446 = Gates.mul gate_421 (4738381338321616896:F) ∧
    ∃gate_447, gate_447 = Gates.add gate_445 gate_446 ∧
    AesDecodeWord_4 gate_447 fun gate_448 =>
    SpreadByteLookup (Plaintext.get (0 : Fin 16)) fun gate_449 =>
    SpreadByteLookup (Plaintext.get (1 : Fin 16)) fun gate_450 =>
    SpreadByteLookup (Plaintext.get (2 : Fin 16)) fun gate_451 =>
    SpreadByteLookup (Plaintext.get (3 : Fin 16)) fun gate_452 =>
    SpreadByteLookup (Plaintext.get (4 : Fin 16)) fun gate_453 =>
    SpreadByteLookup (Plaintext.get (5 : Fin 16)) fun gate_454 =>
    SpreadByteLookup (Plaintext.get (6 : Fin 16)) fun gate_455 =>
    SpreadByteLookup (Plaintext.get (7 : Fin 16)) fun gate_456 =>
    SpreadByteLookup (Plaintext.get (8 : Fin 16)) fun gate_457 =>
    SpreadByteLookup (Plaintext.get (9 : Fin 16)) fun gate_458 =>
    SpreadByteLookup (Plaintext.get (10 : Fin 16)) fun gate_459 =>
    SpreadByteLookup (Plaintext.get (11 : Fin 16)) fun gate_460 =>
    SpreadByteLookup (Plaintext.get (12 : Fin 16)) fun gate_461 =>
    SpreadByteLookup (Plaintext.get (13 : Fin 16)) fun gate_462 =>
    SpreadByteLookup (Plaintext.get (14 : Fin 16)) fun gate_463 =>
    SpreadByteLookup (Plaintext.get (15 : Fin 16)) fun gate_464 =>
    AesRoundColumn_4_4 vec![(gate_439.get (0 : Fin 4)), (gate_448.get (1 : Fin 4)), ((gate_397.get (1 : Fin 2)).get (14 : Fin 240)), (gate_430.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (20 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (21 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (22 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (23 : Fin 240))] fun gate_465 =>
    AesRoundColumn_4_4 vec![(gate_448.get (0 : Fin 4)), ((gate_397.get (1 : Fin 2)).get (13 : Fin 240)), (gate_430.get (2 : Fin 4)), (gate_439.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (24 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (25 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (26 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (27 : Fin 240))] fun gate_466 =>
    AesRoundColumn_4_4 vec![((gate_397.get (1 : Fin 2)).get (12 : Fin 240)), (gate_430.get (1 : Fin 4)), (gate_439.get (2 : Fin 4)), (gate_448.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (28 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (29 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (30 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (31 : Fin 240))] fun gate_467 =>
    ∃gate_468, gate_468 = Gates.mul ((gate_397.get (0 : Fin 2)).get (16 : Fin 240)) (1:F) ∧
    ∃gate_469, gate_469 = Gates.add (0:F) gate_468 ∧
    ∃gate_470, gate_470 = Gates.mul ((gate_397.get (0 : Fin 2)).get (17 : Fin 240)) (1679616:F) ∧
    ∃gate_471, gate_471 = Gates.add gate_469 gate_470 ∧
    ∃gate_472, gate_472 = Gates.mul ((gate_397.get (0 : Fin 2)).get (18 : Fin 240)) (2821109907456:F) ∧
    ∃gate_473, gate_473 = Gates.add gate_471 gate_472 ∧
    ∃gate_474, gate_474 = Gates.mul ((gate_397.get (0 : Fin 2)).get (19 : Fin 240)) (4738381338321616896:F) ∧
    ∃gate_475, gate_475 = Gates.add gate_473 gate_474 ∧
    ∃gate_476, gate_476 = Gates.add (gate_430.get (0 : Fin 4)) (0:F) ∧
    SubstitutionLookup gate_476 fun gate_477 =>
    ∃gate_478, gate_478 = Gates.add gate_475 gate_477 ∧
    ∃gate_479, gate_479 = Gates.add (gate_439.get (1 : Fin 4)) (256:F) ∧
    SubstitutionLookup gate_479 fun gate_480 =>
    ∃gate_481, gate_481 = Gates.add gate_478 gate_480 ∧
    ∃gate_482, gate_482 = Gates.add (gate_448.get (2 : Fin 4)) (512:F) ∧
    SubstitutionLookup gate_482 fun gate_483 =>
    ∃gate_484, gate_484 = Gates.add gate_481 gate_483 ∧
    AesCounterByte_2 ((gate_397.get (0 : Fin 2)).get (15 : Fin 240)) fun gate_485 =>
    ∃gate_486, gate_486 = Gates.add gate_485 (768:F) ∧
    SubstitutionLookup gate_486 fun gate_487 =>
    ∃gate_488, gate_488 = Gates.add gate_484 gate_487 ∧
    AesDecodeWord_4 gate_488 fun gate_489 =>
    AesRoundColumn_4_4 vec![(gate_489.get (0 : Fin 4)), (gate_465.get (1 : Fin 4)), (gate_466.get (2 : Fin 4)), (gate_467.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (32 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (33 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (34 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (35 : Fin 240))] fun gate_490 =>
    AesRoundColumn_4_4 vec![(gate_465.get (0 : Fin 4)), (gate_466.get (1 : Fin 4)), (gate_467.get (2 : Fin 4)), (gate_489.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (36 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (37 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (38 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (39 : Fin 240))] fun gate_491 =>
    AesRoundColumn_4_4 vec![(gate_466.get (0 : Fin 4)), (gate_467.get (1 : Fin 4)), (gate_489.get (2 : Fin 4)), (gate_465.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (40 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (41 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (42 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (43 : Fin 240))] fun gate_492 =>
    AesRoundColumn_4_4 vec![(gate_467.get (0 : Fin 4)), (gate_489.get (1 : Fin 4)), (gate_465.get (2 : Fin 4)), (gate_466.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (44 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (45 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (46 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (47 : Fin 240))] fun gate_493 =>
    AesRoundColumn_4_4 vec![(gate_490.get (0 : Fin 4)), (gate_491.get (1 : Fin 4)), (gate_492.get (2 : Fin 4)), (gate_493.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (48 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (49 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (50 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (51 : Fin 240))] fun gate_494 =>
    AesRoundColumn_4_4 vec![(gate_491.get (0 : Fin 4)), (gate_492.get (1 : Fin 4)), (gate_493.get (2 : Fin 4)), (gate_490.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (52 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (53 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (54 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (55 : Fin 240))] fun gate_495 =>
    AesRoundColumn_4_4 vec![(gate_492.get (0 : Fin 4)), (gate_493.get (1 : Fin 4)), (gate_490.get (2 : Fin 4)), (gate_491.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (56 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (57 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (58 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (59 : Fin 240))] fun gate_496 =>
    AesRoundColumn_4_4 vec![(gate_493.get (0 : Fin 4)), (gate_490.get (1 : Fin 4)), (gate_491.get (2 : Fin 4)), (gate_492.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (60 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (61 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (62 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (63 : Fin 240))] fun gate_497 =>
    AesRoundColumn_4_4 vec![(gate_494.get (0 : Fin 4)), (gate_495.get (1 : Fin 4)), (gate_496.get (2 : Fin 4)), (gate_497.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (64 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (65 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (66 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (67 : Fin 240))] fun gate_498 =>
    AesRoundColumn_4_4 vec![(gate_495.get (0 : Fin 4)), (gate_496.get (1 : Fin 4)), (gate_497.get (2 : Fin 4)), (gate_494.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (68 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (69 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (70 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (71 : Fin 240))] fun gate_499 =>
    AesRoundColumn_4_4 vec![(gate_496.get (0 : Fin 4)), (gate_497.get (1 : Fin 4)), (gate_494.get (2 : Fin 4)), (gate_495.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (72 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (73 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (74 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (75 : Fin 240))] fun gate_500 =>
    AesRoundColumn_4_4 vec![(gate_497.get (0 : Fin 4)), (gate_494.get (1 : Fin 4)), (gate_495.get (2 : Fin 4)), (gate_496.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (76 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (77 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (78 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (79 : Fin 240))] fun gate_501 =>
    AesRoundColumn_4_4 vec![(gate_498.get (0 : Fin 4)), (gate_499.get (1 : Fin 4)), (gate_500.get (2 : Fin 4)), (gate_501.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (80 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (81 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (82 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (83 : Fin 240))] fun gate_502 =>
    AesRoundColumn_4_4 vec![(gate_499.get (0 : Fin 4)), (gate_500.get (1 : Fin 4)), (gate_501.get (2 : Fin 4)), (gate_498.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (84 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (85 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (86 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (87 : Fin 240))] fun gate_503 =>
    AesRoundColumn_4_4 vec![(gate_500.get (0 : Fin 4)), (gate_501.get (1 : Fin 4)), (gate_498.get (2 : Fin 4)), (gate_499.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (88 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (89 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (90 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (91 : Fin 240))] fun gate_504 =>
    AesRoundColumn_4_4 vec![(gate_501.get (0 : Fin 4)), (gate_498.get (1 : Fin 4)), (gate_499.get (2 : Fin 4)), (gate_500.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (92 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (93 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (94 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (95 : Fin 240))] fun gate_505 =>
    AesRoundColumn_4_4 vec![(gate_502.get (0 : Fin 4)), (gate_503.get (1 : Fin 4)), (gate_504.get (2 : Fin 4)), (gate_505.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (96 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (97 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (98 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (99 : Fin 240))] fun gate_506 =>
    AesRoundColumn_4_4 vec![(gate_503.get (0 : Fin 4)), (gate_504.get (1 : Fin 4)), (gate_505.get (2 : Fin 4)), (gate_502.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (100 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (101 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (102 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (103 : Fin 240))] fun gate_507 =>
    AesRoundColumn_4_4 vec![(gate_504.get (0 : Fin 4)), (gate_505.get (1 : Fin 4)), (gate_502.get (2 : Fin 4)), (gate_503.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (104 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (105 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (106 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (107 : Fin 240))] fun gate_508 =>
    AesRoundColumn_4_4 vec![(gate_505.get (0 : Fin 4)), (gate_502.get (1 : Fin 4)), (gate_503.get (2 : Fin 4)), (gate_504.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (108 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (109 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (110 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (111 : Fin 240))] fun gate_509 =>
    AesRoundColumn_4_4 vec![(gate_506.get (0 : Fin 4)), (gate_507.get (1 : Fin 4)), (gate_508.get (2 : Fin 4)), (gate_509.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (112 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (113 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (114 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (115 : Fin 240))] fun gate_510 =>
    AesRoundColumn_4_4 vec![(gate_507.get (0 : Fin 4)), (gate_508.get (1 : Fin 4)), (gate_509.get (2 : Fin 4)), (gate_506.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (116 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (117 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (118 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (119 : Fin 240))] fun gate_511 =>
    AesRoundColumn_4_4 vec![(gate_508.get (0 : Fin 4)), (gate_509.get (1 : Fin 4)), (gate_506.get (2 : Fin 4)), (gate_507.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (120 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (121 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (122 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (123 : Fin 240))] fun gate_512 =>
    AesRoundColumn_4_4 vec![(gate_509.get (0 : Fin 4)), (gate_506.get (1 : Fin 4)), (gate_507.get (2 : Fin 4)), (gate_508.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (124 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (125 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (126 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (127 : Fin 240))] fun gate_513 =>
    AesRoundColumn_4_4 vec![(gate_510.get (0 : Fin 4)), (gate_511.get (1 : Fin 4)), (gate_512.get (2 : Fin 4)), (gate_513.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (128 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (129 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (130 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (131 : Fin 240))] fun gate_514 =>
    AesRoundColumn_4_4 vec![(gate_511.get (0 : Fin 4)), (gate_512.get (1 : Fin 4)), (gate_513.get (2 : Fin 4)), (gate_510.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (132 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (133 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (134 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (135 : Fin 240))] fun gate_515 =>
    AesRoundColumn_4_4 vec![(gate_512.get (0 : Fin 4)), (gate_513.get (1 : Fin 4)), (gate_510.get (2 : Fin 4)), (gate_511.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (136 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (137 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (138 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (139 : Fin 240))] fun gate_516 =>
    AesRoundColumn_4_4 vec![(gate_513.get (0 : Fin 4)), (gate_510.get (1 : Fin 4)), (gate_511.get (2 : Fin 4)), (gate_512.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (140 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (141 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (142 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (143 : Fin 240))] fun gate_517 =>
    AesRoundColumn_4_4 vec![(gate_514.get (0 : Fin 4)), (gate_515.get (1 : Fin 4)), (gate_516.get (2 : Fin 4)), (gate_517.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (144 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (145 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (146 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (147 : Fin 240))] fun gate_518 =>
    AesRoundColumn_4_4 vec![(gate_515.get (0 : Fin 4)), (gate_516.get (1 : Fin 4)), (gate_517.get (2 : Fin 4)), (gate_514.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (148 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (149 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (150 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (151 : Fin 240))] fun gate_519 =>
    AesRoundColumn_4_4 vec![(gate_516.get (0 : Fin 4)), (gate_517.get (1 : Fin 4)), (gate_514.get (2 : Fin 4)), (gate_515.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (152 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (153 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (154 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (155 : Fin 240))] fun gate_520 =>
    AesRoundColumn_4_4 vec![(gate_517.get (0 : Fin 4)), (gate_514.get (1 : Fin 4)), (gate_515.get (2 : Fin 4)), (gate_516.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (156 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (157 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (158 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (159 : Fin 240))] fun gate_521 =>
    AesRoundColumn_4_4 vec![(gate_518.get (0 : Fin 4)), (gate_519.get (1 : Fin 4)), (gate_520.get (2 : Fin 4)), (gate_521.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (160 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (161 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (162 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (163 : Fin 240))] fun gate_522 =>
    AesRoundColumn_4_4 vec![(gate_519.get (0 : Fin 4)), (gate_520.get (1 : Fin 4)), (gate_521.get (2 : Fin 4)), (gate_518.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (164 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (165 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (166 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (167 : Fin 240))] fun gate_523 =>
    AesRoundColumn_4_4 vec![(gate_520.get (0 : Fin 4)), (gate_521.get (1 : Fin 4)), (gate_518.get (2 : Fin 4)), (gate_519.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (168 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (169 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (170 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (171 : Fin 240))] fun gate_524 =>
    AesRoundColumn_4_4 vec![(gate_521.get (0 : Fin 4)), (gate_518.get (1 : Fin 4)), (gate_519.get (2 : Fin 4)), (gate_520.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (172 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (173 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (174 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (175 : Fin 240))] fun gate_525 =>
    AesRoundColumn_4_4 vec![(gate_522.get (0 : Fin 4)), (gate_523.get (1 : Fin 4)), (gate_524.get (2 : Fin 4)), (gate_525.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (176 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (177 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (178 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (179 : Fin 240))] fun gate_526 =>
    AesRoundColumn_4_4 vec![(gate_523.get (0 : Fin 4)), (gate_524.get (1 : Fin 4)), (gate_525.get (2 : Fin 4)), (gate_522.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (180 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (181 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (182 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (183 : Fin 240))] fun gate_527 =>
    AesRoundColumn_4_4 vec![(gate_524.get (0 : Fin 4)), (gate_525.get (1 : Fin 4)), (gate_522.get (2 : Fin 4)), (gate_523.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (184 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (185 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (186 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (187 : Fin 240))] fun gate_528 =>
    AesRoundColumn_4_4 vec![(gate_525.get (0 : Fin 4)), (gate_522.get (1 : Fin 4)), (gate_523.get (2 : Fin 4)), (gate_524.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (188 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (189 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (190 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (191 : Fin 240))] fun gate_529 =>
    AesRoundColumn_4_4 vec![(gate_526.get (0 : Fin 4)), (gate_527.get (1 : Fin 4)), (gate_528.get (2 : Fin 4)), (gate_529.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (192 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (193 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (194 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (195 : Fin 240))] fun gate_530 =>
    AesRoundColumn_4_4 vec![(gate_527.get (0 : Fin 4)), (gate_528.get (1 : Fin 4)), (gate_529.get (2 : Fin 4)), (gate_526.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (196 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (197 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (198 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (199 : Fin 240))] fun gate_531 =>
    AesRoundColumn_4_4 vec![(gate_528.get (0 : Fin 4)), (gate_529.get (1 : Fin 4)), (gate_526.get (2 : Fin 4)), (gate_527.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (200 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (201 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (202 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (203 : Fin 240))] fun gate_532 =>
    AesRoundColumn_4_4 vec![(gate_529.get (0 : Fin 4)), (gate_526.get (1 : Fin 4)), (gate_527.get (2 : Fin 4)), (gate_528.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (204 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (205 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (206 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (207 : Fin 240))] fun gate_533 =>
    AesRoundColumn_4_4 vec![(gate_530.get (0 : Fin 4)), (gate_531.get (1 : Fin 4)), (gate_532.get (2 : Fin 4)), (gate_533.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (208 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (209 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (210 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (211 : Fin 240))] fun gate_534 =>
    AesRoundColumn_4_4 vec![(gate_531.get (0 : Fin 4)), (gate_532.get (1 : Fin 4)), (gate_533.get (2 : Fin 4)), (gate_530.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (212 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (213 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (214 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (215 : Fin 240))] fun gate_535 =>
    AesRoundColumn_4_4 vec![(gate_532.get (0 : Fin 4)), (gate_533.get (1 : Fin 4)), (gate_530.get (2 : Fin 4)), (gate_531.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (216 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (217 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (218 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (219 : Fin 240))] fun gate_536 =>
    AesRoundColumn_4_4 vec![(gate_533.get (0 : Fin 4)), (gate_530.get (1 : Fin 4)), (gate_531.get (2 : Fin 4)), (gate_532.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (220 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (221 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (222 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (223 : Fin 240))] fun gate_537 =>
    AesFinalRound_16_16_16 vec![(gate_534.get (0 : Fin 4)), (gate_534.get (1 : Fin 4)), (gate_534.get (2 : Fin 4)), (gate_534.get (3 : Fin 4)), (gate_535.get (0 : Fin 4)), (gate_535.get (1 : Fin 4)), (gate_535.get (2 : Fin 4)), (gate_535.get (3 : Fin 4)), (gate_536.get (0 : Fin 4)), (gate_536.get (1 : Fin 4)), (gate_536.get (2 : Fin 4)), (gate_536.get (3 : Fin 4)), (gate_537.get (0 : Fin 4)), (gate_537.get (1 : Fin 4)), (gate_537.get (2 : Fin 4)), (gate_537.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (224 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (225 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (226 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (227 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (228 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (229 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (230 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (231 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (232 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (233 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (234 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (235 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (236 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (237 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (238 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (239 : Fin 240))] vec![gate_449, gate_450, gate_451, gate_452, gate_453, gate_454, gate_455, gate_456, gate_457, gate_458, gate_459, gate_460, gate_461, gate_462, gate_463, gate_464] fun gate_538 =>
    Gates.eq gate_259 RecipientLo ∧
    Gates.eq gate_263 RecipientHi ∧
    Gates.eq (gate_364.get (0 : Fin 2)) EphemeralLo ∧
    Gates.eq (gate_364.get (1 : Fin 2)) EphemeralHi ∧
    Gates.eq (gate_538.get (0 : Fin 16)) (Ciphertext.get (0 : Fin 16)) ∧
    Gates.eq (gate_538.get (1 : Fin 16)) (Ciphertext.get (1 : Fin 16)) ∧
    Gates.eq (gate_538.get (2 : Fin 16)) (Ciphertext.get (2 : Fin 16)) ∧
    Gates.eq (gate_538.get (3 : Fin 16)) (Ciphertext.get (3 : Fin 16)) ∧
    Gates.eq (gate_538.get (4 : Fin 16)) (Ciphertext.get (4 : Fin 16)) ∧
    Gates.eq (gate_538.get (5 : Fin 16)) (Ciphertext.get (5 : Fin 16)) ∧
    Gates.eq (gate_538.get (6 : Fin 16)) (Ciphertext.get (6 : Fin 16)) ∧
    Gates.eq (gate_538.get (7 : Fin 16)) (Ciphertext.get (7 : Fin 16)) ∧
    Gates.eq (gate_538.get (8 : Fin 16)) (Ciphertext.get (8 : Fin 16)) ∧
    Gates.eq (gate_538.get (9 : Fin 16)) (Ciphertext.get (9 : Fin 16)) ∧
    Gates.eq (gate_538.get (10 : Fin 16)) (Ciphertext.get (10 : Fin 16)) ∧
    Gates.eq (gate_538.get (11 : Fin 16)) (Ciphertext.get (11 : Fin 16)) ∧
    Gates.eq (gate_538.get (12 : Fin 16)) (Ciphertext.get (12 : Fin 16)) ∧
    Gates.eq (gate_538.get (13 : Fin 16)) (Ciphertext.get (13 : Fin 16)) ∧
    Gates.eq (gate_538.get (14 : Fin 16)) (Ciphertext.get (14 : Fin 16)) ∧
    Gates.eq (gate_538.get (15 : Fin 16)) (Ciphertext.get (15 : Fin 16)) ∧
    True

def Envelope_32_65_16_16_p1 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Plaintext: List.Vector F 16) (RecipientLo: F) (RecipientHi: F) (EphemeralLo: F) (EphemeralHi: F) (Ciphertext: List.Vector F 16) (gate_72: F) (gate_80: F) (gate_88: F) (gate_96: F) (gate_104: F) (gate_112: F) (gate_120: F) (gate_128: F) (gate_136: F) (gate_144: F) (gate_152: F) (gate_160: F) (gate_168: F) (gate_176: F) (gate_184: F) (gate_192: F) (gate_198: F) (gate_199: F): Prop :=
    ∃gate_200, gate_200 = Gates.add gate_199 (RecipientPk.get (1 : Fin 65)) ∧
    ∃gate_201, gate_201 = Gates.mul gate_200 (256:F) ∧
    ∃gate_202, gate_202 = Gates.add gate_201 (RecipientPk.get (2 : Fin 65)) ∧
    ∃gate_203, gate_203 = Gates.mul gate_202 (256:F) ∧
    ∃gate_204, gate_204 = Gates.add gate_203 (RecipientPk.get (3 : Fin 65)) ∧
    ∃gate_205, gate_205 = Gates.mul gate_204 (256:F) ∧
    ∃gate_206, gate_206 = Gates.add gate_205 (RecipientPk.get (4 : Fin 65)) ∧
    ∃gate_207, gate_207 = Gates.mul gate_206 (256:F) ∧
    ∃gate_208, gate_208 = Gates.add gate_207 (RecipientPk.get (5 : Fin 65)) ∧
    ∃gate_209, gate_209 = Gates.mul gate_208 (256:F) ∧
    ∃gate_210, gate_210 = Gates.add gate_209 (RecipientPk.get (6 : Fin 65)) ∧
    ∃gate_211, gate_211 = Gates.mul gate_210 (256:F) ∧
    ∃gate_212, gate_212 = Gates.add gate_211 (RecipientPk.get (7 : Fin 65)) ∧
    ∃gate_213, gate_213 = Gates.mul gate_212 (256:F) ∧
    ∃gate_214, gate_214 = Gates.add gate_213 (RecipientPk.get (8 : Fin 65)) ∧
    ∃gate_215, gate_215 = Gates.mul gate_214 (256:F) ∧
    ∃gate_216, gate_216 = Gates.add gate_215 (RecipientPk.get (9 : Fin 65)) ∧
    ∃gate_217, gate_217 = Gates.mul gate_216 (256:F) ∧
    ∃gate_218, gate_218 = Gates.add gate_217 (RecipientPk.get (10 : Fin 65)) ∧
    ∃gate_219, gate_219 = Gates.mul gate_218 (256:F) ∧
    ∃gate_220, gate_220 = Gates.add gate_219 (RecipientPk.get (11 : Fin 65)) ∧
    ∃gate_221, gate_221 = Gates.mul gate_220 (256:F) ∧
    ∃gate_222, gate_222 = Gates.add gate_221 (RecipientPk.get (12 : Fin 65)) ∧
    ∃gate_223, gate_223 = Gates.mul gate_222 (256:F) ∧
    ∃gate_224, gate_224 = Gates.add gate_223 (RecipientPk.get (13 : Fin 65)) ∧
    ∃gate_225, gate_225 = Gates.mul gate_224 (256:F) ∧
    ∃gate_226, gate_226 = Gates.add gate_225 (RecipientPk.get (14 : Fin 65)) ∧
    ∃gate_227, gate_227 = Gates.mul gate_226 (256:F) ∧
    ∃gate_228, gate_228 = Gates.add gate_227 (RecipientPk.get (15 : Fin 65)) ∧
    ∃gate_229, gate_229 = Gates.mul gate_228 (256:F) ∧
    ∃gate_230, gate_230 = Gates.add gate_229 (RecipientPk.get (16 : Fin 65)) ∧
    ∃gate_231, gate_231 = Gates.mul gate_230 (256:F) ∧
    ∃gate_232, gate_232 = Gates.add gate_231 (RecipientPk.get (17 : Fin 65)) ∧
    ∃gate_233, gate_233 = Gates.mul gate_232 (256:F) ∧
    ∃gate_234, gate_234 = Gates.add gate_233 (RecipientPk.get (18 : Fin 65)) ∧
    ∃gate_235, gate_235 = Gates.mul gate_234 (256:F) ∧
    ∃gate_236, gate_236 = Gates.add gate_235 (RecipientPk.get (19 : Fin 65)) ∧
    ∃gate_237, gate_237 = Gates.mul gate_236 (256:F) ∧
    ∃gate_238, gate_238 = Gates.add gate_237 (RecipientPk.get (20 : Fin 65)) ∧
    ∃gate_239, gate_239 = Gates.mul gate_238 (256:F) ∧
    ∃gate_240, gate_240 = Gates.add gate_239 (RecipientPk.get (21 : Fin 65)) ∧
    ∃gate_241, gate_241 = Gates.mul gate_240 (256:F) ∧
    ∃gate_242, gate_242 = Gates.add gate_241 (RecipientPk.get (22 : Fin 65)) ∧
    ∃gate_243, gate_243 = Gates.mul gate_242 (256:F) ∧
    ∃gate_244, gate_244 = Gates.add gate_243 (RecipientPk.get (23 : Fin 65)) ∧
    ∃gate_245, gate_245 = Gates.mul gate_244 (256:F) ∧
    ∃gate_246, gate_246 = Gates.add gate_245 (RecipientPk.get (24 : Fin 65)) ∧
    ∃gate_247, gate_247 = Gates.mul gate_246 (256:F) ∧
    ∃gate_248, gate_248 = Gates.add gate_247 (RecipientPk.get (25 : Fin 65)) ∧
    ∃gate_249, gate_249 = Gates.mul gate_248 (256:F) ∧
    ∃gate_250, gate_250 = Gates.add gate_249 (RecipientPk.get (26 : Fin 65)) ∧
    ∃gate_251, gate_251 = Gates.mul gate_250 (256:F) ∧
    ∃gate_252, gate_252 = Gates.add gate_251 (RecipientPk.get (27 : Fin 65)) ∧
    ∃gate_253, gate_253 = Gates.mul gate_252 (256:F) ∧
    ∃gate_254, gate_254 = Gates.add gate_253 (RecipientPk.get (28 : Fin 65)) ∧
    ∃gate_255, gate_255 = Gates.mul gate_254 (256:F) ∧
    ∃gate_256, gate_256 = Gates.add gate_255 (RecipientPk.get (29 : Fin 65)) ∧
    ∃gate_257, gate_257 = Gates.mul gate_256 (256:F) ∧
    ∃gate_258, gate_258 = Gates.add gate_257 (RecipientPk.get (30 : Fin 65)) ∧
    ∃gate_259, gate_259 = Gates.add gate_198 gate_258 ∧
    ∃gate_260, gate_260 = Gates.mul (0:F) (256:F) ∧
    ∃gate_261, gate_261 = Gates.add gate_260 (RecipientPk.get (31 : Fin 65)) ∧
    ∃gate_262, gate_262 = Gates.mul gate_261 (256:F) ∧
    ∃gate_263, gate_263 = Gates.add gate_262 (RecipientPk.get (32 : Fin 65)) ∧
    RangeCheck 8 (EphemeralSk.get (0 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (1 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (2 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (3 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (4 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (5 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (6 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (7 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (8 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (9 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (10 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (11 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (12 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (13 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (14 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (15 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (16 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (17 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (18 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (19 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (20 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (21 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (22 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (23 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (24 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (25 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (26 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (27 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (28 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (29 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (30 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (31 : Fin 32)) ∧
    ∃gate_296, gate_296 = Gates.mul (0:F) (256:F) ∧
    ∃gate_297, gate_297 = Gates.add gate_296 (EphemeralSk.get (28 : Fin 32)) ∧
    ∃gate_298, gate_298 = Gates.mul gate_297 (256:F) ∧
    ∃gate_299, gate_299 = Gates.add gate_298 (EphemeralSk.get (29 : Fin 32)) ∧
    ∃gate_300, gate_300 = Gates.mul gate_299 (256:F) ∧
    ∃gate_301, gate_301 = Gates.add gate_300 (EphemeralSk.get (30 : Fin 32)) ∧
    ∃gate_302, gate_302 = Gates.mul gate_301 (256:F) ∧
    ∃gate_303, gate_303 = Gates.add gate_302 (EphemeralSk.get (31 : Fin 32)) ∧
    ∃gate_304, gate_304 = Gates.mul (0:F) (256:F) ∧
    ∃gate_305, gate_305 = Gates.add gate_304 (EphemeralSk.get (24 : Fin 32)) ∧
    ∃gate_306, gate_306 = Gates.mul gate_305 (256:F) ∧
    ∃gate_307, gate_307 = Gates.add gate_306 (EphemeralSk.get (25 : Fin 32)) ∧
    ∃gate_308, gate_308 = Gates.mul gate_307 (256:F) ∧
    ∃gate_309, gate_309 = Gates.add gate_308 (EphemeralSk.get (26 : Fin 32)) ∧
    ∃gate_310, gate_310 = Gates.mul gate_309 (256:F) ∧
    ∃gate_311, gate_311 = Gates.add gate_310 (EphemeralSk.get (27 : Fin 32)) ∧
    ∃gate_312, gate_312 = Gates.mul (0:F) (256:F) ∧
    ∃gate_313, gate_313 = Gates.add gate_312 (EphemeralSk.get (20 : Fin 32)) ∧
    ∃gate_314, gate_314 = Gates.mul gate_313 (256:F) ∧
    ∃gate_315, gate_315 = Gates.add gate_314 (EphemeralSk.get (21 : Fin 32)) ∧
    ∃gate_316, gate_316 = Gates.mul gate_315 (256:F) ∧
    ∃gate_317, gate_317 = Gates.add gate_316 (EphemeralSk.get (22 : Fin 32)) ∧
    ∃gate_318, gate_318 = Gates.mul gate_317 (256:F) ∧
    ∃gate_319, gate_319 = Gates.add gate_318 (EphemeralSk.get (23 : Fin 32)) ∧
    ∃gate_320, gate_320 = Gates.mul (0:F) (256:F) ∧
    ∃gate_321, gate_321 = Gates.add gate_320 (EphemeralSk.get (16 : Fin 32)) ∧
    ∃gate_322, gate_322 = Gates.mul gate_321 (256:F) ∧
    ∃gate_323, gate_323 = Gates.add gate_322 (EphemeralSk.get (17 : Fin 32)) ∧
    ∃gate_324, gate_324 = Gates.mul gate_323 (256:F) ∧
    ∃gate_325, gate_325 = Gates.add gate_324 (EphemeralSk.get (18 : Fin 32)) ∧
    ∃gate_326, gate_326 = Gates.mul gate_325 (256:F) ∧
    ∃gate_327, gate_327 = Gates.add gate_326 (EphemeralSk.get (19 : Fin 32)) ∧
    ∃gate_328, gate_328 = Gates.mul (0:F) (256:F) ∧
    ∃gate_329, gate_329 = Gates.add gate_328 (EphemeralSk.get (12 : Fin 32)) ∧
    ∃gate_330, gate_330 = Gates.mul gate_329 (256:F) ∧
    ∃gate_331, gate_331 = Gates.add gate_330 (EphemeralSk.get (13 : Fin 32)) ∧
    ∃gate_332, gate_332 = Gates.mul gate_331 (256:F) ∧
    ∃gate_333, gate_333 = Gates.add gate_332 (EphemeralSk.get (14 : Fin 32)) ∧
    ∃gate_334, gate_334 = Gates.mul gate_333 (256:F) ∧
    ∃gate_335, gate_335 = Gates.add gate_334 (EphemeralSk.get (15 : Fin 32)) ∧
    ∃gate_336, gate_336 = Gates.mul (0:F) (256:F) ∧
    ∃gate_337, gate_337 = Gates.add gate_336 (EphemeralSk.get (8 : Fin 32)) ∧
    ∃gate_338, gate_338 = Gates.mul gate_337 (256:F) ∧
    ∃gate_339, gate_339 = Gates.add gate_338 (EphemeralSk.get (9 : Fin 32)) ∧
    ∃gate_340, gate_340 = Gates.mul gate_339 (256:F) ∧
    ∃gate_341, gate_341 = Gates.add gate_340 (EphemeralSk.get (10 : Fin 32)) ∧
    ∃gate_342, gate_342 = Gates.mul gate_341 (256:F) ∧
    ∃gate_343, gate_343 = Gates.add gate_342 (EphemeralSk.get (11 : Fin 32)) ∧
    ∃gate_344, gate_344 = Gates.mul (0:F) (256:F) ∧
    ∃gate_345, gate_345 = Gates.add gate_344 (EphemeralSk.get (4 : Fin 32)) ∧
    ∃gate_346, gate_346 = Gates.mul gate_345 (256:F) ∧
    ∃gate_347, gate_347 = Gates.add gate_346 (EphemeralSk.get (5 : Fin 32)) ∧
    ∃gate_348, gate_348 = Gates.mul gate_347 (256:F) ∧
    ∃gate_349, gate_349 = Gates.add gate_348 (EphemeralSk.get (6 : Fin 32)) ∧
    ∃gate_350, gate_350 = Gates.mul gate_349 (256:F) ∧
    ∃gate_351, gate_351 = Gates.add gate_350 (EphemeralSk.get (7 : Fin 32)) ∧
    ∃gate_352, gate_352 = Gates.mul (0:F) (256:F) ∧
    ∃gate_353, gate_353 = Gates.add gate_352 (EphemeralSk.get (0 : Fin 32)) ∧
    ∃gate_354, gate_354 = Gates.mul gate_353 (256:F) ∧
    ∃gate_355, gate_355 = Gates.add gate_354 (EphemeralSk.get (1 : Fin 32)) ∧
    ∃gate_356, gate_356 = Gates.mul gate_355 (256:F) ∧
    ∃gate_357, gate_357 = Gates.add gate_356 (EphemeralSk.get (2 : Fin 32)) ∧
    ∃gate_358, gate_358 = Gates.mul gate_357 (256:F) ∧
    ∃gate_359, gate_359 = Gates.add gate_358 (EphemeralSk.get (3 : Fin 32)) ∧
    ScalarMulChecked_8_8_8_h9a706aba vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] vec![gate_303, gate_311, gate_319, gate_327, gate_335, gate_343, gate_351, gate_359] fun gate_360 =>
    ScalarMulBase_8_h3037b025 vec![gate_303, gate_311, gate_319, gate_327, gate_335, gate_343, gate_351, gate_359] fun gate_361 =>
    AssertCanonical_8_0_hcc2f8a19 (gate_361.get (0 : Fin 2)) ∧
    AssertCanonical_8_0_hcc2f8a19 (gate_361.get (1 : Fin 2)) ∧
    CompressedPacking_8_8_32 (gate_361.get (0 : Fin 2)) (gate_361.get (1 : Fin 2)) fun gate_364 =>
    AssertCanonical_8_0_hcc2f8a19 (gate_360.get (0 : Fin 2)) ∧
    SplitLowBits_8_32 ((gate_360.get (0 : Fin 2)).get (0 : Fin 8)) fun gate_366 =>
    ∃gate_367, gate_367 = Gates.mul ((gate_360.get (0 : Fin 2)).get (1 : Fin 8)) (16777216:F) ∧
    ∃gate_368, gate_368 = Gates.add (gate_366.get (0 : Fin 2)) gate_367 ∧
    ∃gate_369, gate_369 = Gates.mul ((gate_360.get (0 : Fin 2)).get (2 : Fin 8)) (72057594037927936:F) ∧
    ∃gate_370, gate_370 = Gates.add gate_368 gate_369 ∧
    ∃gate_371, gate_371 = Gates.mul ((gate_360.get (0 : Fin 2)).get (3 : Fin 8)) K_1 ∧
    ∃gate_372, gate_372 = Gates.add gate_370 gate_371 ∧
    ∃gate_373, gate_373 = Gates.mul ((gate_360.get (0 : Fin 2)).get (4 : Fin 8)) K_2 ∧
    ∃gate_374, gate_374 = Gates.add gate_372 gate_373 ∧
    ∃gate_375, gate_375 = Gates.mul ((gate_360.get (0 : Fin 2)).get (5 : Fin 8)) K_3 ∧
    ∃gate_376, gate_376 = Gates.add gate_374 gate_375 ∧
    ∃gate_377, gate_377 = Gates.mul ((gate_360.get (0 : Fin 2)).get (6 : Fin 8)) K_4 ∧
    ∃gate_378, gate_378 = Gates.add gate_376 gate_377 ∧
    ∃gate_379, gate_379 = Gates.mul ((gate_360.get (0 : Fin 2)).get (7 : Fin 8)) K_5 ∧
    ∃gate_380, gate_380 = Gates.add gate_378 gate_379 ∧
    Poseidon_7 vec![(1414350163:F), gate_380, (gate_366.get (1 : Fin 2)), (gate_364.get (0 : Fin 2)), (gate_364.get (1 : Fin 2)), gate_259, gate_263] (0:F) fun gate_381 =>
    ∃gate_382, gate_382 = Gates.mul (0:F) (256:F) ∧
    ∃gate_383, gate_383 = Gates.add gate_382 (84:F) ∧
    ∃gate_384, gate_384 = Gates.mul gate_383 (256:F) ∧
    ∃gate_385, gate_385 = Gates.add gate_384 (77:F) ∧
    ∃gate_386, gate_386 = Gates.mul gate_385 (256:F) ∧
    ∃gate_387, gate_387 = Gates.add gate_386 (69:F) ∧
    ∃gate_388, gate_388 = Gates.mul gate_387 (256:F) ∧
    ∃gate_389, gate_389 = Gates.add gate_388 (67:F) ∧
    Poseidon_3 vec![(1414353737:F), gate_381, gate_389] (0:F) fun gate_390 =>
    Poseidon_2 vec![(1414353739:F), gate_390] (0:F) fun gate_391 =>
    Poseidon_2 vec![(1414353740:F), gate_390] (0:F) fun gate_392 =>
    FieldBytesBE_32 gate_391 fun gate_393 =>
    FieldBytesBE_32 gate_392 fun gate_394 =>
    Poseidon_2 vec![(1414353742:F), gate_390] (0:F) fun gate_395 =>
    FieldBytesBE_32 gate_395 fun gate_396 =>
    AesKeyExpansion_32 vec![(gate_394.get (16 : Fin 32)), (gate_394.get (17 : Fin 32)), (gate_394.get (18 : Fin 32)), (gate_394.get (19 : Fin 32)), (gate_394.get (20 : Fin 32)), (gate_394.get (21 : Fin 32)), (gate_394.get (22 : Fin 32)), (gate_394.get (23 : Fin 32)), (gate_394.get (24 : Fin 32)), (gate_394.get (25 : Fin 32)), (gate_394.get (26 : Fin 32)), (gate_394.get (27 : Fin 32)), (gate_394.get (28 : Fin 32)), (gate_394.get (29 : Fin 32)), (gate_394.get (30 : Fin 32)), (gate_394.get (31 : Fin 32)), (gate_393.get (16 : Fin 32)), (gate_393.get (17 : Fin 32)), (gate_393.get (18 : Fin 32)), (gate_393.get (19 : Fin 32)), (gate_393.get (20 : Fin 32)), (gate_393.get (21 : Fin 32)), (gate_393.get (22 : Fin 32)), (gate_393.get (23 : Fin 32)), (gate_393.get (24 : Fin 32)), (gate_393.get (25 : Fin 32)), (gate_393.get (26 : Fin 32)), (gate_393.get (27 : Fin 32)), (gate_393.get (28 : Fin 32)), (gate_393.get (29 : Fin 32)), (gate_393.get (30 : Fin 32)), (gate_393.get (31 : Fin 32))] fun gate_397 =>
    SpreadByteLookup (gate_396.get (20 : Fin 32)) fun gate_398 =>
    SpreadByteLookup (gate_396.get (21 : Fin 32)) fun gate_399 =>
    Envelope_32_65_16_16_p2 EphemeralSk RecipientPk Plaintext RecipientLo RecipientHi EphemeralLo EphemeralHi Ciphertext gate_259 gate_263 gate_364 gate_396 gate_397 gate_398 gate_399

def Envelope_32_65_16_16 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Plaintext: List.Vector F 16) (RecipientLo: F) (RecipientHi: F) (EphemeralLo: F) (EphemeralHi: F) (Ciphertext: List.Vector F 16): Prop :=
    Gates.eq (RecipientPk.get (0 : Fin 65)) (4:F) ∧
    RangeCheck 8 (RecipientPk.get (1 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (2 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (3 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (4 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (5 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (6 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (7 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (8 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (9 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (10 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (11 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (12 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (13 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (14 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (15 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (16 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (17 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (18 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (19 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (20 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (21 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (22 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (23 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (24 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (25 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (26 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (27 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (28 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (29 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (30 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (31 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (32 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (33 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (34 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (35 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (36 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (37 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (38 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (39 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (40 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (41 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (42 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (43 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (44 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (45 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (46 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (47 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (48 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (49 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (50 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (51 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (52 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (53 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (54 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (55 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (56 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (57 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (58 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (59 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (60 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (61 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (62 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (63 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (64 : Fin 65)) ∧
    ∃gate_65, gate_65 = Gates.mul (0:F) (256:F) ∧
    ∃gate_66, gate_66 = Gates.add gate_65 (RecipientPk.get (29 : Fin 65)) ∧
    ∃gate_67, gate_67 = Gates.mul gate_66 (256:F) ∧
    ∃gate_68, gate_68 = Gates.add gate_67 (RecipientPk.get (30 : Fin 65)) ∧
    ∃gate_69, gate_69 = Gates.mul gate_68 (256:F) ∧
    ∃gate_70, gate_70 = Gates.add gate_69 (RecipientPk.get (31 : Fin 65)) ∧
    ∃gate_71, gate_71 = Gates.mul gate_70 (256:F) ∧
    ∃gate_72, gate_72 = Gates.add gate_71 (RecipientPk.get (32 : Fin 65)) ∧
    ∃gate_73, gate_73 = Gates.mul (0:F) (256:F) ∧
    ∃gate_74, gate_74 = Gates.add gate_73 (RecipientPk.get (25 : Fin 65)) ∧
    ∃gate_75, gate_75 = Gates.mul gate_74 (256:F) ∧
    ∃gate_76, gate_76 = Gates.add gate_75 (RecipientPk.get (26 : Fin 65)) ∧
    ∃gate_77, gate_77 = Gates.mul gate_76 (256:F) ∧
    ∃gate_78, gate_78 = Gates.add gate_77 (RecipientPk.get (27 : Fin 65)) ∧
    ∃gate_79, gate_79 = Gates.mul gate_78 (256:F) ∧
    ∃gate_80, gate_80 = Gates.add gate_79 (RecipientPk.get (28 : Fin 65)) ∧
    ∃gate_81, gate_81 = Gates.mul (0:F) (256:F) ∧
    ∃gate_82, gate_82 = Gates.add gate_81 (RecipientPk.get (21 : Fin 65)) ∧
    ∃gate_83, gate_83 = Gates.mul gate_82 (256:F) ∧
    ∃gate_84, gate_84 = Gates.add gate_83 (RecipientPk.get (22 : Fin 65)) ∧
    ∃gate_85, gate_85 = Gates.mul gate_84 (256:F) ∧
    ∃gate_86, gate_86 = Gates.add gate_85 (RecipientPk.get (23 : Fin 65)) ∧
    ∃gate_87, gate_87 = Gates.mul gate_86 (256:F) ∧
    ∃gate_88, gate_88 = Gates.add gate_87 (RecipientPk.get (24 : Fin 65)) ∧
    ∃gate_89, gate_89 = Gates.mul (0:F) (256:F) ∧
    ∃gate_90, gate_90 = Gates.add gate_89 (RecipientPk.get (17 : Fin 65)) ∧
    ∃gate_91, gate_91 = Gates.mul gate_90 (256:F) ∧
    ∃gate_92, gate_92 = Gates.add gate_91 (RecipientPk.get (18 : Fin 65)) ∧
    ∃gate_93, gate_93 = Gates.mul gate_92 (256:F) ∧
    ∃gate_94, gate_94 = Gates.add gate_93 (RecipientPk.get (19 : Fin 65)) ∧
    ∃gate_95, gate_95 = Gates.mul gate_94 (256:F) ∧
    ∃gate_96, gate_96 = Gates.add gate_95 (RecipientPk.get (20 : Fin 65)) ∧
    ∃gate_97, gate_97 = Gates.mul (0:F) (256:F) ∧
    ∃gate_98, gate_98 = Gates.add gate_97 (RecipientPk.get (13 : Fin 65)) ∧
    ∃gate_99, gate_99 = Gates.mul gate_98 (256:F) ∧
    ∃gate_100, gate_100 = Gates.add gate_99 (RecipientPk.get (14 : Fin 65)) ∧
    ∃gate_101, gate_101 = Gates.mul gate_100 (256:F) ∧
    ∃gate_102, gate_102 = Gates.add gate_101 (RecipientPk.get (15 : Fin 65)) ∧
    ∃gate_103, gate_103 = Gates.mul gate_102 (256:F) ∧
    ∃gate_104, gate_104 = Gates.add gate_103 (RecipientPk.get (16 : Fin 65)) ∧
    ∃gate_105, gate_105 = Gates.mul (0:F) (256:F) ∧
    ∃gate_106, gate_106 = Gates.add gate_105 (RecipientPk.get (9 : Fin 65)) ∧
    ∃gate_107, gate_107 = Gates.mul gate_106 (256:F) ∧
    ∃gate_108, gate_108 = Gates.add gate_107 (RecipientPk.get (10 : Fin 65)) ∧
    ∃gate_109, gate_109 = Gates.mul gate_108 (256:F) ∧
    ∃gate_110, gate_110 = Gates.add gate_109 (RecipientPk.get (11 : Fin 65)) ∧
    ∃gate_111, gate_111 = Gates.mul gate_110 (256:F) ∧
    ∃gate_112, gate_112 = Gates.add gate_111 (RecipientPk.get (12 : Fin 65)) ∧
    ∃gate_113, gate_113 = Gates.mul (0:F) (256:F) ∧
    ∃gate_114, gate_114 = Gates.add gate_113 (RecipientPk.get (5 : Fin 65)) ∧
    ∃gate_115, gate_115 = Gates.mul gate_114 (256:F) ∧
    ∃gate_116, gate_116 = Gates.add gate_115 (RecipientPk.get (6 : Fin 65)) ∧
    ∃gate_117, gate_117 = Gates.mul gate_116 (256:F) ∧
    ∃gate_118, gate_118 = Gates.add gate_117 (RecipientPk.get (7 : Fin 65)) ∧
    ∃gate_119, gate_119 = Gates.mul gate_118 (256:F) ∧
    ∃gate_120, gate_120 = Gates.add gate_119 (RecipientPk.get (8 : Fin 65)) ∧
    ∃gate_121, gate_121 = Gates.mul (0:F) (256:F) ∧
    ∃gate_122, gate_122 = Gates.add gate_121 (RecipientPk.get (1 : Fin 65)) ∧
    ∃gate_123, gate_123 = Gates.mul gate_122 (256:F) ∧
    ∃gate_124, gate_124 = Gates.add gate_123 (RecipientPk.get (2 : Fin 65)) ∧
    ∃gate_125, gate_125 = Gates.mul gate_124 (256:F) ∧
    ∃gate_126, gate_126 = Gates.add gate_125 (RecipientPk.get (3 : Fin 65)) ∧
    ∃gate_127, gate_127 = Gates.mul gate_126 (256:F) ∧
    ∃gate_128, gate_128 = Gates.add gate_127 (RecipientPk.get (4 : Fin 65)) ∧
    ∃gate_129, gate_129 = Gates.mul (0:F) (256:F) ∧
    ∃gate_130, gate_130 = Gates.add gate_129 (RecipientPk.get (61 : Fin 65)) ∧
    ∃gate_131, gate_131 = Gates.mul gate_130 (256:F) ∧
    ∃gate_132, gate_132 = Gates.add gate_131 (RecipientPk.get (62 : Fin 65)) ∧
    ∃gate_133, gate_133 = Gates.mul gate_132 (256:F) ∧
    ∃gate_134, gate_134 = Gates.add gate_133 (RecipientPk.get (63 : Fin 65)) ∧
    ∃gate_135, gate_135 = Gates.mul gate_134 (256:F) ∧
    ∃gate_136, gate_136 = Gates.add gate_135 (RecipientPk.get (64 : Fin 65)) ∧
    ∃gate_137, gate_137 = Gates.mul (0:F) (256:F) ∧
    ∃gate_138, gate_138 = Gates.add gate_137 (RecipientPk.get (57 : Fin 65)) ∧
    ∃gate_139, gate_139 = Gates.mul gate_138 (256:F) ∧
    ∃gate_140, gate_140 = Gates.add gate_139 (RecipientPk.get (58 : Fin 65)) ∧
    ∃gate_141, gate_141 = Gates.mul gate_140 (256:F) ∧
    ∃gate_142, gate_142 = Gates.add gate_141 (RecipientPk.get (59 : Fin 65)) ∧
    ∃gate_143, gate_143 = Gates.mul gate_142 (256:F) ∧
    ∃gate_144, gate_144 = Gates.add gate_143 (RecipientPk.get (60 : Fin 65)) ∧
    ∃gate_145, gate_145 = Gates.mul (0:F) (256:F) ∧
    ∃gate_146, gate_146 = Gates.add gate_145 (RecipientPk.get (53 : Fin 65)) ∧
    ∃gate_147, gate_147 = Gates.mul gate_146 (256:F) ∧
    ∃gate_148, gate_148 = Gates.add gate_147 (RecipientPk.get (54 : Fin 65)) ∧
    ∃gate_149, gate_149 = Gates.mul gate_148 (256:F) ∧
    ∃gate_150, gate_150 = Gates.add gate_149 (RecipientPk.get (55 : Fin 65)) ∧
    ∃gate_151, gate_151 = Gates.mul gate_150 (256:F) ∧
    ∃gate_152, gate_152 = Gates.add gate_151 (RecipientPk.get (56 : Fin 65)) ∧
    ∃gate_153, gate_153 = Gates.mul (0:F) (256:F) ∧
    ∃gate_154, gate_154 = Gates.add gate_153 (RecipientPk.get (49 : Fin 65)) ∧
    ∃gate_155, gate_155 = Gates.mul gate_154 (256:F) ∧
    ∃gate_156, gate_156 = Gates.add gate_155 (RecipientPk.get (50 : Fin 65)) ∧
    ∃gate_157, gate_157 = Gates.mul gate_156 (256:F) ∧
    ∃gate_158, gate_158 = Gates.add gate_157 (RecipientPk.get (51 : Fin 65)) ∧
    ∃gate_159, gate_159 = Gates.mul gate_158 (256:F) ∧
    ∃gate_160, gate_160 = Gates.add gate_159 (RecipientPk.get (52 : Fin 65)) ∧
    ∃gate_161, gate_161 = Gates.mul (0:F) (256:F) ∧
    ∃gate_162, gate_162 = Gates.add gate_161 (RecipientPk.get (45 : Fin 65)) ∧
    ∃gate_163, gate_163 = Gates.mul gate_162 (256:F) ∧
    ∃gate_164, gate_164 = Gates.add gate_163 (RecipientPk.get (46 : Fin 65)) ∧
    ∃gate_165, gate_165 = Gates.mul gate_164 (256:F) ∧
    ∃gate_166, gate_166 = Gates.add gate_165 (RecipientPk.get (47 : Fin 65)) ∧
    ∃gate_167, gate_167 = Gates.mul gate_166 (256:F) ∧
    ∃gate_168, gate_168 = Gates.add gate_167 (RecipientPk.get (48 : Fin 65)) ∧
    ∃gate_169, gate_169 = Gates.mul (0:F) (256:F) ∧
    ∃gate_170, gate_170 = Gates.add gate_169 (RecipientPk.get (41 : Fin 65)) ∧
    ∃gate_171, gate_171 = Gates.mul gate_170 (256:F) ∧
    ∃gate_172, gate_172 = Gates.add gate_171 (RecipientPk.get (42 : Fin 65)) ∧
    ∃gate_173, gate_173 = Gates.mul gate_172 (256:F) ∧
    ∃gate_174, gate_174 = Gates.add gate_173 (RecipientPk.get (43 : Fin 65)) ∧
    ∃gate_175, gate_175 = Gates.mul gate_174 (256:F) ∧
    ∃gate_176, gate_176 = Gates.add gate_175 (RecipientPk.get (44 : Fin 65)) ∧
    ∃gate_177, gate_177 = Gates.mul (0:F) (256:F) ∧
    ∃gate_178, gate_178 = Gates.add gate_177 (RecipientPk.get (37 : Fin 65)) ∧
    ∃gate_179, gate_179 = Gates.mul gate_178 (256:F) ∧
    ∃gate_180, gate_180 = Gates.add gate_179 (RecipientPk.get (38 : Fin 65)) ∧
    ∃gate_181, gate_181 = Gates.mul gate_180 (256:F) ∧
    ∃gate_182, gate_182 = Gates.add gate_181 (RecipientPk.get (39 : Fin 65)) ∧
    ∃gate_183, gate_183 = Gates.mul gate_182 (256:F) ∧
    ∃gate_184, gate_184 = Gates.add gate_183 (RecipientPk.get (40 : Fin 65)) ∧
    ∃gate_185, gate_185 = Gates.mul (0:F) (256:F) ∧
    ∃gate_186, gate_186 = Gates.add gate_185 (RecipientPk.get (33 : Fin 65)) ∧
    ∃gate_187, gate_187 = Gates.mul gate_186 (256:F) ∧
    ∃gate_188, gate_188 = Gates.add gate_187 (RecipientPk.get (34 : Fin 65)) ∧
    ∃gate_189, gate_189 = Gates.mul gate_188 (256:F) ∧
    ∃gate_190, gate_190 = Gates.add gate_189 (RecipientPk.get (35 : Fin 65)) ∧
    ∃gate_191, gate_191 = Gates.mul gate_190 (256:F) ∧
    ∃gate_192, gate_192 = Gates.add gate_191 (RecipientPk.get (36 : Fin 65)) ∧
    AssertCanonical_8_0_hcc2f8a19 vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] ∧
    AssertCanonical_8_0_hcc2f8a19 vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] ∧
    AssertOnCurve_8_8_h2c0228bb vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] ∧
    SplitLowBits_1_8 (RecipientPk.get (64 : Fin 65)) fun gate_196 =>
    ∃gate_197, gate_197 = Gates.add (2:F) (gate_196.get (1 : Fin 2)) ∧
    ∃gate_198, gate_198 = Gates.mul gate_197 K_0 ∧
    ∃gate_199, gate_199 = Gates.mul (0:F) (256:F) ∧
    Envelope_32_65_16_16_p1 EphemeralSk RecipientPk Plaintext RecipientLo RecipientHi EphemeralLo EphemeralHi Ciphertext gate_72 gate_80 gate_88 gate_96 gate_104 gate_112 gate_120 gate_128 gate_136 gate_144 gate_152 gate_160 gate_168 gate_176 gate_184 gate_192 gate_198 gate_199

def EnvelopeMerge_32_65_40_4_p3 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Plaintext: List.Vector F 40) (Context: F) (Elements: List.Vector F 4) (Blinding: F) (gate_259: F) (gate_263: F) (gate_364: List.Vector F 2) (gate_381: F) (gate_397: List.Vector (List.Vector F 240) 2) (gate_465: List.Vector F 4) (gate_466: List.Vector F 4) (gate_467: List.Vector F 4) (gate_484: F) (gate_538: List.Vector F 16) (gate_539: F) (gate_540: F) (gate_541: F) (gate_542: F) (gate_543: F) (gate_544: F) (gate_545: F) (gate_546: F) (gate_547: F) (gate_548: F) (gate_549: F) (gate_550: F) (gate_551: F) (gate_552: F) (gate_553: F) (gate_554: F) (gate_596: List.Vector F 4) (gate_597: List.Vector F 4) (gate_598: List.Vector F 4) (gate_599: List.Vector F 4): Prop :=
    AesRoundColumn_4_4 vec![(gate_596.get (0 : Fin 4)), (gate_597.get (1 : Fin 4)), (gate_598.get (2 : Fin 4)), (gate_599.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (192 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (193 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (194 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (195 : Fin 240))] fun gate_600 =>
    AesRoundColumn_4_4 vec![(gate_597.get (0 : Fin 4)), (gate_598.get (1 : Fin 4)), (gate_599.get (2 : Fin 4)), (gate_596.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (196 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (197 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (198 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (199 : Fin 240))] fun gate_601 =>
    AesRoundColumn_4_4 vec![(gate_598.get (0 : Fin 4)), (gate_599.get (1 : Fin 4)), (gate_596.get (2 : Fin 4)), (gate_597.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (200 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (201 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (202 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (203 : Fin 240))] fun gate_602 =>
    AesRoundColumn_4_4 vec![(gate_599.get (0 : Fin 4)), (gate_596.get (1 : Fin 4)), (gate_597.get (2 : Fin 4)), (gate_598.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (204 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (205 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (206 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (207 : Fin 240))] fun gate_603 =>
    AesRoundColumn_4_4 vec![(gate_600.get (0 : Fin 4)), (gate_601.get (1 : Fin 4)), (gate_602.get (2 : Fin 4)), (gate_603.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (208 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (209 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (210 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (211 : Fin 240))] fun gate_604 =>
    AesRoundColumn_4_4 vec![(gate_601.get (0 : Fin 4)), (gate_602.get (1 : Fin 4)), (gate_603.get (2 : Fin 4)), (gate_600.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (212 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (213 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (214 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (215 : Fin 240))] fun gate_605 =>
    AesRoundColumn_4_4 vec![(gate_602.get (0 : Fin 4)), (gate_603.get (1 : Fin 4)), (gate_600.get (2 : Fin 4)), (gate_601.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (216 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (217 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (218 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (219 : Fin 240))] fun gate_606 =>
    AesRoundColumn_4_4 vec![(gate_603.get (0 : Fin 4)), (gate_600.get (1 : Fin 4)), (gate_601.get (2 : Fin 4)), (gate_602.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (220 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (221 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (222 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (223 : Fin 240))] fun gate_607 =>
    AesFinalRound_16_16_16 vec![(gate_604.get (0 : Fin 4)), (gate_604.get (1 : Fin 4)), (gate_604.get (2 : Fin 4)), (gate_604.get (3 : Fin 4)), (gate_605.get (0 : Fin 4)), (gate_605.get (1 : Fin 4)), (gate_605.get (2 : Fin 4)), (gate_605.get (3 : Fin 4)), (gate_606.get (0 : Fin 4)), (gate_606.get (1 : Fin 4)), (gate_606.get (2 : Fin 4)), (gate_606.get (3 : Fin 4)), (gate_607.get (0 : Fin 4)), (gate_607.get (1 : Fin 4)), (gate_607.get (2 : Fin 4)), (gate_607.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (224 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (225 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (226 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (227 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (228 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (229 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (230 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (231 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (232 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (233 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (234 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (235 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (236 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (237 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (238 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (239 : Fin 240))] vec![gate_539, gate_540, gate_541, gate_542, gate_543, gate_544, gate_545, gate_546, gate_547, gate_548, gate_549, gate_550, gate_551, gate_552, gate_553, gate_554] fun gate_608 =>
    SpreadByteLookup (Plaintext.get (32 : Fin 40)) fun gate_609 =>
    SpreadByteLookup (Plaintext.get (33 : Fin 40)) fun gate_610 =>
    SpreadByteLookup (Plaintext.get (34 : Fin 40)) fun gate_611 =>
    SpreadByteLookup (Plaintext.get (35 : Fin 40)) fun gate_612 =>
    SpreadByteLookup (Plaintext.get (36 : Fin 40)) fun gate_613 =>
    SpreadByteLookup (Plaintext.get (37 : Fin 40)) fun gate_614 =>
    SpreadByteLookup (Plaintext.get (38 : Fin 40)) fun gate_615 =>
    SpreadByteLookup (Plaintext.get (39 : Fin 40)) fun gate_616 =>
    AesCounterByte_4 ((gate_397.get (0 : Fin 2)).get (15 : Fin 240)) fun gate_617 =>
    ∃gate_618, gate_618 = Gates.add gate_617 (768:F) ∧
    SubstitutionLookup gate_618 fun gate_619 =>
    ∃gate_620, gate_620 = Gates.add gate_484 gate_619 ∧
    AesDecodeWord_4 gate_620 fun gate_621 =>
    AesRoundColumn_4_4 vec![(gate_621.get (0 : Fin 4)), (gate_465.get (1 : Fin 4)), (gate_466.get (2 : Fin 4)), (gate_467.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (32 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (33 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (34 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (35 : Fin 240))] fun gate_622 =>
    AesRoundColumn_4_4 vec![(gate_465.get (0 : Fin 4)), (gate_466.get (1 : Fin 4)), (gate_467.get (2 : Fin 4)), (gate_621.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (36 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (37 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (38 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (39 : Fin 240))] fun gate_623 =>
    AesRoundColumn_4_4 vec![(gate_466.get (0 : Fin 4)), (gate_467.get (1 : Fin 4)), (gate_621.get (2 : Fin 4)), (gate_465.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (40 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (41 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (42 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (43 : Fin 240))] fun gate_624 =>
    AesRoundColumn_4_4 vec![(gate_467.get (0 : Fin 4)), (gate_621.get (1 : Fin 4)), (gate_465.get (2 : Fin 4)), (gate_466.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (44 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (45 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (46 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (47 : Fin 240))] fun gate_625 =>
    AesRoundColumn_4_4 vec![(gate_622.get (0 : Fin 4)), (gate_623.get (1 : Fin 4)), (gate_624.get (2 : Fin 4)), (gate_625.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (48 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (49 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (50 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (51 : Fin 240))] fun gate_626 =>
    AesRoundColumn_4_4 vec![(gate_623.get (0 : Fin 4)), (gate_624.get (1 : Fin 4)), (gate_625.get (2 : Fin 4)), (gate_622.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (52 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (53 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (54 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (55 : Fin 240))] fun gate_627 =>
    AesRoundColumn_4_4 vec![(gate_624.get (0 : Fin 4)), (gate_625.get (1 : Fin 4)), (gate_622.get (2 : Fin 4)), (gate_623.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (56 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (57 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (58 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (59 : Fin 240))] fun gate_628 =>
    AesRoundColumn_4_4 vec![(gate_625.get (0 : Fin 4)), (gate_622.get (1 : Fin 4)), (gate_623.get (2 : Fin 4)), (gate_624.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (60 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (61 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (62 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (63 : Fin 240))] fun gate_629 =>
    AesRoundColumn_4_4 vec![(gate_626.get (0 : Fin 4)), (gate_627.get (1 : Fin 4)), (gate_628.get (2 : Fin 4)), (gate_629.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (64 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (65 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (66 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (67 : Fin 240))] fun gate_630 =>
    AesRoundColumn_4_4 vec![(gate_627.get (0 : Fin 4)), (gate_628.get (1 : Fin 4)), (gate_629.get (2 : Fin 4)), (gate_626.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (68 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (69 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (70 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (71 : Fin 240))] fun gate_631 =>
    AesRoundColumn_4_4 vec![(gate_628.get (0 : Fin 4)), (gate_629.get (1 : Fin 4)), (gate_626.get (2 : Fin 4)), (gate_627.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (72 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (73 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (74 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (75 : Fin 240))] fun gate_632 =>
    AesRoundColumn_4_4 vec![(gate_629.get (0 : Fin 4)), (gate_626.get (1 : Fin 4)), (gate_627.get (2 : Fin 4)), (gate_628.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (76 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (77 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (78 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (79 : Fin 240))] fun gate_633 =>
    AesRoundColumn_4_4 vec![(gate_630.get (0 : Fin 4)), (gate_631.get (1 : Fin 4)), (gate_632.get (2 : Fin 4)), (gate_633.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (80 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (81 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (82 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (83 : Fin 240))] fun gate_634 =>
    AesRoundColumn_4_4 vec![(gate_631.get (0 : Fin 4)), (gate_632.get (1 : Fin 4)), (gate_633.get (2 : Fin 4)), (gate_630.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (84 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (85 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (86 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (87 : Fin 240))] fun gate_635 =>
    AesRoundColumn_4_4 vec![(gate_632.get (0 : Fin 4)), (gate_633.get (1 : Fin 4)), (gate_630.get (2 : Fin 4)), (gate_631.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (88 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (89 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (90 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (91 : Fin 240))] fun gate_636 =>
    AesRoundColumn_4_4 vec![(gate_633.get (0 : Fin 4)), (gate_630.get (1 : Fin 4)), (gate_631.get (2 : Fin 4)), (gate_632.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (92 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (93 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (94 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (95 : Fin 240))] fun gate_637 =>
    AesRoundColumn_4_4 vec![(gate_634.get (0 : Fin 4)), (gate_635.get (1 : Fin 4)), (gate_636.get (2 : Fin 4)), (gate_637.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (96 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (97 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (98 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (99 : Fin 240))] fun gate_638 =>
    AesRoundColumn_4_4 vec![(gate_635.get (0 : Fin 4)), (gate_636.get (1 : Fin 4)), (gate_637.get (2 : Fin 4)), (gate_634.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (100 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (101 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (102 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (103 : Fin 240))] fun gate_639 =>
    AesRoundColumn_4_4 vec![(gate_636.get (0 : Fin 4)), (gate_637.get (1 : Fin 4)), (gate_634.get (2 : Fin 4)), (gate_635.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (104 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (105 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (106 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (107 : Fin 240))] fun gate_640 =>
    AesRoundColumn_4_4 vec![(gate_637.get (0 : Fin 4)), (gate_634.get (1 : Fin 4)), (gate_635.get (2 : Fin 4)), (gate_636.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (108 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (109 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (110 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (111 : Fin 240))] fun gate_641 =>
    AesRoundColumn_4_4 vec![(gate_638.get (0 : Fin 4)), (gate_639.get (1 : Fin 4)), (gate_640.get (2 : Fin 4)), (gate_641.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (112 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (113 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (114 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (115 : Fin 240))] fun gate_642 =>
    AesRoundColumn_4_4 vec![(gate_639.get (0 : Fin 4)), (gate_640.get (1 : Fin 4)), (gate_641.get (2 : Fin 4)), (gate_638.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (116 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (117 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (118 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (119 : Fin 240))] fun gate_643 =>
    AesRoundColumn_4_4 vec![(gate_640.get (0 : Fin 4)), (gate_641.get (1 : Fin 4)), (gate_638.get (2 : Fin 4)), (gate_639.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (120 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (121 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (122 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (123 : Fin 240))] fun gate_644 =>
    AesRoundColumn_4_4 vec![(gate_641.get (0 : Fin 4)), (gate_638.get (1 : Fin 4)), (gate_639.get (2 : Fin 4)), (gate_640.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (124 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (125 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (126 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (127 : Fin 240))] fun gate_645 =>
    AesRoundColumn_4_4 vec![(gate_642.get (0 : Fin 4)), (gate_643.get (1 : Fin 4)), (gate_644.get (2 : Fin 4)), (gate_645.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (128 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (129 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (130 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (131 : Fin 240))] fun gate_646 =>
    AesRoundColumn_4_4 vec![(gate_643.get (0 : Fin 4)), (gate_644.get (1 : Fin 4)), (gate_645.get (2 : Fin 4)), (gate_642.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (132 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (133 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (134 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (135 : Fin 240))] fun gate_647 =>
    AesRoundColumn_4_4 vec![(gate_644.get (0 : Fin 4)), (gate_645.get (1 : Fin 4)), (gate_642.get (2 : Fin 4)), (gate_643.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (136 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (137 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (138 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (139 : Fin 240))] fun gate_648 =>
    AesRoundColumn_4_4 vec![(gate_645.get (0 : Fin 4)), (gate_642.get (1 : Fin 4)), (gate_643.get (2 : Fin 4)), (gate_644.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (140 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (141 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (142 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (143 : Fin 240))] fun gate_649 =>
    AesRoundColumn_4_4 vec![(gate_646.get (0 : Fin 4)), (gate_647.get (1 : Fin 4)), (gate_648.get (2 : Fin 4)), (gate_649.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (144 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (145 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (146 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (147 : Fin 240))] fun gate_650 =>
    AesRoundColumn_4_4 vec![(gate_647.get (0 : Fin 4)), (gate_648.get (1 : Fin 4)), (gate_649.get (2 : Fin 4)), (gate_646.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (148 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (149 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (150 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (151 : Fin 240))] fun gate_651 =>
    AesRoundColumn_4_4 vec![(gate_648.get (0 : Fin 4)), (gate_649.get (1 : Fin 4)), (gate_646.get (2 : Fin 4)), (gate_647.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (152 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (153 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (154 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (155 : Fin 240))] fun gate_652 =>
    AesRoundColumn_4_4 vec![(gate_649.get (0 : Fin 4)), (gate_646.get (1 : Fin 4)), (gate_647.get (2 : Fin 4)), (gate_648.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (156 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (157 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (158 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (159 : Fin 240))] fun gate_653 =>
    AesRoundColumn_4_4 vec![(gate_650.get (0 : Fin 4)), (gate_651.get (1 : Fin 4)), (gate_652.get (2 : Fin 4)), (gate_653.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (160 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (161 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (162 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (163 : Fin 240))] fun gate_654 =>
    AesRoundColumn_4_4 vec![(gate_651.get (0 : Fin 4)), (gate_652.get (1 : Fin 4)), (gate_653.get (2 : Fin 4)), (gate_650.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (164 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (165 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (166 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (167 : Fin 240))] fun gate_655 =>
    AesRoundColumn_4_4 vec![(gate_652.get (0 : Fin 4)), (gate_653.get (1 : Fin 4)), (gate_650.get (2 : Fin 4)), (gate_651.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (168 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (169 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (170 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (171 : Fin 240))] fun gate_656 =>
    AesRoundColumn_4_4 vec![(gate_653.get (0 : Fin 4)), (gate_650.get (1 : Fin 4)), (gate_651.get (2 : Fin 4)), (gate_652.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (172 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (173 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (174 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (175 : Fin 240))] fun gate_657 =>
    AesRoundColumn_4_4 vec![(gate_654.get (0 : Fin 4)), (gate_655.get (1 : Fin 4)), (gate_656.get (2 : Fin 4)), (gate_657.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (176 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (177 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (178 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (179 : Fin 240))] fun gate_658 =>
    AesRoundColumn_4_4 vec![(gate_655.get (0 : Fin 4)), (gate_656.get (1 : Fin 4)), (gate_657.get (2 : Fin 4)), (gate_654.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (180 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (181 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (182 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (183 : Fin 240))] fun gate_659 =>
    AesRoundColumn_4_4 vec![(gate_656.get (0 : Fin 4)), (gate_657.get (1 : Fin 4)), (gate_654.get (2 : Fin 4)), (gate_655.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (184 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (185 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (186 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (187 : Fin 240))] fun gate_660 =>
    AesRoundColumn_4_4 vec![(gate_657.get (0 : Fin 4)), (gate_654.get (1 : Fin 4)), (gate_655.get (2 : Fin 4)), (gate_656.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (188 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (189 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (190 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (191 : Fin 240))] fun gate_661 =>
    AesRoundColumn_4_4 vec![(gate_658.get (0 : Fin 4)), (gate_659.get (1 : Fin 4)), (gate_660.get (2 : Fin 4)), (gate_661.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (192 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (193 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (194 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (195 : Fin 240))] fun gate_662 =>
    AesRoundColumn_4_4 vec![(gate_659.get (0 : Fin 4)), (gate_660.get (1 : Fin 4)), (gate_661.get (2 : Fin 4)), (gate_658.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (196 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (197 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (198 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (199 : Fin 240))] fun gate_663 =>
    AesRoundColumn_4_4 vec![(gate_660.get (0 : Fin 4)), (gate_661.get (1 : Fin 4)), (gate_658.get (2 : Fin 4)), (gate_659.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (200 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (201 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (202 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (203 : Fin 240))] fun gate_664 =>
    AesRoundColumn_4_4 vec![(gate_661.get (0 : Fin 4)), (gate_658.get (1 : Fin 4)), (gate_659.get (2 : Fin 4)), (gate_660.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (204 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (205 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (206 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (207 : Fin 240))] fun gate_665 =>
    AesRoundColumn_4_4 vec![(gate_662.get (0 : Fin 4)), (gate_663.get (1 : Fin 4)), (gate_664.get (2 : Fin 4)), (gate_665.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (208 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (209 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (210 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (211 : Fin 240))] fun gate_666 =>
    AesRoundColumn_4_4 vec![(gate_663.get (0 : Fin 4)), (gate_664.get (1 : Fin 4)), (gate_665.get (2 : Fin 4)), (gate_662.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (212 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (213 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (214 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (215 : Fin 240))] fun gate_667 =>
    AesRoundColumn_4_4 vec![(gate_664.get (0 : Fin 4)), (gate_665.get (1 : Fin 4)), (gate_662.get (2 : Fin 4)), (gate_663.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (216 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (217 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (218 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (219 : Fin 240))] fun gate_668 =>
    AesRoundColumn_4_4 vec![(gate_665.get (0 : Fin 4)), (gate_662.get (1 : Fin 4)), (gate_663.get (2 : Fin 4)), (gate_664.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (220 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (221 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (222 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (223 : Fin 240))] fun gate_669 =>
    AesFinalRound_16_8_8 vec![(gate_666.get (0 : Fin 4)), (gate_666.get (1 : Fin 4)), (gate_666.get (2 : Fin 4)), (gate_666.get (3 : Fin 4)), (gate_667.get (0 : Fin 4)), (gate_667.get (1 : Fin 4)), (gate_667.get (2 : Fin 4)), (gate_667.get (3 : Fin 4)), (gate_668.get (0 : Fin 4)), (gate_668.get (1 : Fin 4)), (gate_668.get (2 : Fin 4)), (gate_668.get (3 : Fin 4)), (gate_669.get (0 : Fin 4)), (gate_669.get (1 : Fin 4)), (gate_669.get (2 : Fin 4)), (gate_669.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (224 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (225 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (226 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (227 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (228 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (229 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (230 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (231 : Fin 240))] vec![gate_609, gate_610, gate_611, gate_612, gate_613, gate_614, gate_615, gate_616] fun gate_670 =>
    ∃gate_671, gate_671 = Gates.mul gate_263 K_7180 ∧
    ∃gate_672, gate_672 = Gates.mul (gate_364.get (1 : Fin 2)) K_5 ∧
    ∃gate_673, gate_673 = Gates.mul (0:F) (256:F) ∧
    ∃gate_674, gate_674 = Gates.add gate_673 (gate_538.get (0 : Fin 16)) ∧
    ∃gate_675, gate_675 = Gates.mul gate_674 (256:F) ∧
    ∃gate_676, gate_676 = Gates.add gate_675 (gate_538.get (1 : Fin 16)) ∧
    ∃gate_677, gate_677 = Gates.mul gate_676 (256:F) ∧
    ∃gate_678, gate_678 = Gates.add gate_677 (gate_538.get (2 : Fin 16)) ∧
    ∃gate_679, gate_679 = Gates.mul gate_678 (256:F) ∧
    ∃gate_680, gate_680 = Gates.add gate_679 (gate_538.get (3 : Fin 16)) ∧
    ∃gate_681, gate_681 = Gates.mul gate_680 (256:F) ∧
    ∃gate_682, gate_682 = Gates.add gate_681 (gate_538.get (4 : Fin 16)) ∧
    ∃gate_683, gate_683 = Gates.mul gate_682 (256:F) ∧
    ∃gate_684, gate_684 = Gates.add gate_683 (gate_538.get (5 : Fin 16)) ∧
    ∃gate_685, gate_685 = Gates.mul gate_684 (256:F) ∧
    ∃gate_686, gate_686 = Gates.add gate_685 (gate_538.get (6 : Fin 16)) ∧
    ∃gate_687, gate_687 = Gates.mul gate_686 (256:F) ∧
    ∃gate_688, gate_688 = Gates.add gate_687 (gate_538.get (7 : Fin 16)) ∧
    ∃gate_689, gate_689 = Gates.mul gate_688 (256:F) ∧
    ∃gate_690, gate_690 = Gates.add gate_689 (gate_538.get (8 : Fin 16)) ∧
    ∃gate_691, gate_691 = Gates.mul gate_690 (256:F) ∧
    ∃gate_692, gate_692 = Gates.add gate_691 (gate_538.get (9 : Fin 16)) ∧
    ∃gate_693, gate_693 = Gates.mul gate_692 (256:F) ∧
    ∃gate_694, gate_694 = Gates.add gate_693 (gate_538.get (10 : Fin 16)) ∧
    ∃gate_695, gate_695 = Gates.mul gate_694 (256:F) ∧
    ∃gate_696, gate_696 = Gates.add gate_695 (gate_538.get (11 : Fin 16)) ∧
    ∃gate_697, gate_697 = Gates.mul gate_696 (256:F) ∧
    ∃gate_698, gate_698 = Gates.add gate_697 (gate_538.get (12 : Fin 16)) ∧
    ∃gate_699, gate_699 = Gates.mul gate_698 (256:F) ∧
    ∃gate_700, gate_700 = Gates.add gate_699 (gate_538.get (13 : Fin 16)) ∧
    ∃gate_701, gate_701 = Gates.mul gate_700 (256:F) ∧
    ∃gate_702, gate_702 = Gates.add gate_701 (gate_538.get (14 : Fin 16)) ∧
    ∃gate_703, gate_703 = Gates.mul gate_702 (256:F) ∧
    ∃gate_704, gate_704 = Gates.add gate_703 (gate_538.get (15 : Fin 16)) ∧
    ∃gate_705, gate_705 = Gates.mul gate_704 (256:F) ∧
    ∃gate_706, gate_706 = Gates.add gate_705 (gate_608.get (0 : Fin 16)) ∧
    ∃gate_707, gate_707 = Gates.mul gate_706 (256:F) ∧
    ∃gate_708, gate_708 = Gates.add gate_707 (gate_608.get (1 : Fin 16)) ∧
    ∃gate_709, gate_709 = Gates.mul gate_708 (256:F) ∧
    ∃gate_710, gate_710 = Gates.add gate_709 (gate_608.get (2 : Fin 16)) ∧
    ∃gate_711, gate_711 = Gates.mul gate_710 (256:F) ∧
    ∃gate_712, gate_712 = Gates.add gate_711 (gate_608.get (3 : Fin 16)) ∧
    ∃gate_713, gate_713 = Gates.mul gate_712 (256:F) ∧
    ∃gate_714, gate_714 = Gates.add gate_713 (gate_608.get (4 : Fin 16)) ∧
    ∃gate_715, gate_715 = Gates.mul gate_714 (256:F) ∧
    ∃gate_716, gate_716 = Gates.add gate_715 (gate_608.get (5 : Fin 16)) ∧
    ∃gate_717, gate_717 = Gates.mul gate_716 (256:F) ∧
    ∃gate_718, gate_718 = Gates.add gate_717 (gate_608.get (6 : Fin 16)) ∧
    ∃gate_719, gate_719 = Gates.mul gate_718 (256:F) ∧
    ∃gate_720, gate_720 = Gates.add gate_719 (gate_608.get (7 : Fin 16)) ∧
    ∃gate_721, gate_721 = Gates.mul gate_720 (256:F) ∧
    ∃gate_722, gate_722 = Gates.add gate_721 (gate_608.get (8 : Fin 16)) ∧
    ∃gate_723, gate_723 = Gates.mul gate_722 (256:F) ∧
    ∃gate_724, gate_724 = Gates.add gate_723 (gate_608.get (9 : Fin 16)) ∧
    ∃gate_725, gate_725 = Gates.mul gate_724 (256:F) ∧
    ∃gate_726, gate_726 = Gates.add gate_725 (gate_608.get (10 : Fin 16)) ∧
    ∃gate_727, gate_727 = Gates.add (Gates.add gate_671 gate_672) gate_726 ∧
    ∃gate_728, gate_728 = Gates.mul (0:F) (256:F) ∧
    ∃gate_729, gate_729 = Gates.add gate_728 (gate_608.get (11 : Fin 16)) ∧
    ∃gate_730, gate_730 = Gates.mul gate_729 (256:F) ∧
    ∃gate_731, gate_731 = Gates.add gate_730 (gate_608.get (12 : Fin 16)) ∧
    ∃gate_732, gate_732 = Gates.mul gate_731 (256:F) ∧
    ∃gate_733, gate_733 = Gates.add gate_732 (gate_608.get (13 : Fin 16)) ∧
    ∃gate_734, gate_734 = Gates.mul gate_733 (256:F) ∧
    ∃gate_735, gate_735 = Gates.add gate_734 (gate_608.get (14 : Fin 16)) ∧
    ∃gate_736, gate_736 = Gates.mul gate_735 (256:F) ∧
    ∃gate_737, gate_737 = Gates.add gate_736 (gate_608.get (15 : Fin 16)) ∧
    ∃gate_738, gate_738 = Gates.mul gate_737 (256:F) ∧
    ∃gate_739, gate_739 = Gates.add gate_738 (gate_670.get (0 : Fin 8)) ∧
    ∃gate_740, gate_740 = Gates.mul gate_739 (256:F) ∧
    ∃gate_741, gate_741 = Gates.add gate_740 (gate_670.get (1 : Fin 8)) ∧
    ∃gate_742, gate_742 = Gates.mul gate_741 (256:F) ∧
    ∃gate_743, gate_743 = Gates.add gate_742 (gate_670.get (2 : Fin 8)) ∧
    ∃gate_744, gate_744 = Gates.mul gate_743 (256:F) ∧
    ∃gate_745, gate_745 = Gates.add gate_744 (gate_670.get (3 : Fin 8)) ∧
    ∃gate_746, gate_746 = Gates.mul gate_745 (256:F) ∧
    ∃gate_747, gate_747 = Gates.add gate_746 (gate_670.get (4 : Fin 8)) ∧
    ∃gate_748, gate_748 = Gates.mul gate_747 (256:F) ∧
    ∃gate_749, gate_749 = Gates.add gate_748 (gate_670.get (5 : Fin 8)) ∧
    ∃gate_750, gate_750 = Gates.mul gate_749 (256:F) ∧
    ∃gate_751, gate_751 = Gates.add gate_750 (gate_670.get (6 : Fin 8)) ∧
    ∃gate_752, gate_752 = Gates.mul gate_751 (256:F) ∧
    ∃gate_753, gate_753 = Gates.add gate_752 (gate_670.get (7 : Fin 8)) ∧
    Gates.eq gate_259 (Elements.get (0 : Fin 4)) ∧
    Gates.eq (gate_364.get (0 : Fin 2)) (Elements.get (1 : Fin 4)) ∧
    Gates.eq gate_727 (Elements.get (2 : Fin 4)) ∧
    Gates.eq gate_753 (Elements.get (3 : Fin 4)) ∧
    Poseidon_2 vec![(1414350146:F), gate_381] (0:F) fun gate_758 =>
    Gates.eq gate_758 Blinding ∧
    True

def EnvelopeMerge_32_65_40_4_p2 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Plaintext: List.Vector F 40) (Context: F) (Elements: List.Vector F 4) (Blinding: F) (gate_259: F) (gate_263: F) (gate_364: List.Vector F 2) (gate_381: F) (gate_396: List.Vector F 32) (gate_397: List.Vector (List.Vector F 240) 2) (gate_398: F) (gate_399: F): Prop :=
    SpreadByteLookup (gate_396.get (22 : Fin 32)) fun gate_400 =>
    SpreadByteLookup (gate_396.get (23 : Fin 32)) fun gate_401 =>
    SpreadByteLookup (gate_396.get (24 : Fin 32)) fun gate_402 =>
    SpreadByteLookup (gate_396.get (25 : Fin 32)) fun gate_403 =>
    SpreadByteLookup (gate_396.get (26 : Fin 32)) fun gate_404 =>
    SpreadByteLookup (gate_396.get (27 : Fin 32)) fun gate_405 =>
    SpreadByteLookup (gate_396.get (28 : Fin 32)) fun gate_406 =>
    SpreadByteLookup (gate_396.get (29 : Fin 32)) fun gate_407 =>
    SpreadByteLookup (gate_396.get (30 : Fin 32)) fun gate_408 =>
    SpreadByteLookup (gate_396.get (31 : Fin 32)) fun gate_409 =>
    ∃gate_410, gate_410 = Gates.add gate_398 ((gate_397.get (0 : Fin 2)).get (0 : Fin 240)) ∧
    ∃gate_411, gate_411 = Gates.add gate_399 ((gate_397.get (0 : Fin 2)).get (1 : Fin 240)) ∧
    ∃gate_412, gate_412 = Gates.add gate_400 ((gate_397.get (0 : Fin 2)).get (2 : Fin 240)) ∧
    ∃gate_413, gate_413 = Gates.add gate_401 ((gate_397.get (0 : Fin 2)).get (3 : Fin 240)) ∧
    ∃gate_414, gate_414 = Gates.add gate_402 ((gate_397.get (0 : Fin 2)).get (4 : Fin 240)) ∧
    ∃gate_415, gate_415 = Gates.add gate_403 ((gate_397.get (0 : Fin 2)).get (5 : Fin 240)) ∧
    ∃gate_416, gate_416 = Gates.add gate_404 ((gate_397.get (0 : Fin 2)).get (6 : Fin 240)) ∧
    ∃gate_417, gate_417 = Gates.add gate_405 ((gate_397.get (0 : Fin 2)).get (7 : Fin 240)) ∧
    ∃gate_418, gate_418 = Gates.add gate_406 ((gate_397.get (0 : Fin 2)).get (8 : Fin 240)) ∧
    ∃gate_419, gate_419 = Gates.add gate_407 ((gate_397.get (0 : Fin 2)).get (9 : Fin 240)) ∧
    ∃gate_420, gate_420 = Gates.add gate_408 ((gate_397.get (0 : Fin 2)).get (10 : Fin 240)) ∧
    ∃gate_421, gate_421 = Gates.add gate_409 ((gate_397.get (0 : Fin 2)).get (11 : Fin 240)) ∧
    ∃gate_422, gate_422 = Gates.mul gate_410 (1:F) ∧
    ∃gate_423, gate_423 = Gates.add (0:F) gate_422 ∧
    ∃gate_424, gate_424 = Gates.mul gate_411 (1679616:F) ∧
    ∃gate_425, gate_425 = Gates.add gate_423 gate_424 ∧
    ∃gate_426, gate_426 = Gates.mul gate_412 (2821109907456:F) ∧
    ∃gate_427, gate_427 = Gates.add gate_425 gate_426 ∧
    ∃gate_428, gate_428 = Gates.mul gate_413 (4738381338321616896:F) ∧
    ∃gate_429, gate_429 = Gates.add gate_427 gate_428 ∧
    AesDecodeWord_4 gate_429 fun gate_430 =>
    ∃gate_431, gate_431 = Gates.mul gate_414 (1:F) ∧
    ∃gate_432, gate_432 = Gates.add (0:F) gate_431 ∧
    ∃gate_433, gate_433 = Gates.mul gate_415 (1679616:F) ∧
    ∃gate_434, gate_434 = Gates.add gate_432 gate_433 ∧
    ∃gate_435, gate_435 = Gates.mul gate_416 (2821109907456:F) ∧
    ∃gate_436, gate_436 = Gates.add gate_434 gate_435 ∧
    ∃gate_437, gate_437 = Gates.mul gate_417 (4738381338321616896:F) ∧
    ∃gate_438, gate_438 = Gates.add gate_436 gate_437 ∧
    AesDecodeWord_4 gate_438 fun gate_439 =>
    ∃gate_440, gate_440 = Gates.mul gate_418 (1:F) ∧
    ∃gate_441, gate_441 = Gates.add (0:F) gate_440 ∧
    ∃gate_442, gate_442 = Gates.mul gate_419 (1679616:F) ∧
    ∃gate_443, gate_443 = Gates.add gate_441 gate_442 ∧
    ∃gate_444, gate_444 = Gates.mul gate_420 (2821109907456:F) ∧
    ∃gate_445, gate_445 = Gates.add gate_443 gate_444 ∧
    ∃gate_446, gate_446 = Gates.mul gate_421 (4738381338321616896:F) ∧
    ∃gate_447, gate_447 = Gates.add gate_445 gate_446 ∧
    AesDecodeWord_4 gate_447 fun gate_448 =>
    SpreadByteLookup (Plaintext.get (0 : Fin 40)) fun gate_449 =>
    SpreadByteLookup (Plaintext.get (1 : Fin 40)) fun gate_450 =>
    SpreadByteLookup (Plaintext.get (2 : Fin 40)) fun gate_451 =>
    SpreadByteLookup (Plaintext.get (3 : Fin 40)) fun gate_452 =>
    SpreadByteLookup (Plaintext.get (4 : Fin 40)) fun gate_453 =>
    SpreadByteLookup (Plaintext.get (5 : Fin 40)) fun gate_454 =>
    SpreadByteLookup (Plaintext.get (6 : Fin 40)) fun gate_455 =>
    SpreadByteLookup (Plaintext.get (7 : Fin 40)) fun gate_456 =>
    SpreadByteLookup (Plaintext.get (8 : Fin 40)) fun gate_457 =>
    SpreadByteLookup (Plaintext.get (9 : Fin 40)) fun gate_458 =>
    SpreadByteLookup (Plaintext.get (10 : Fin 40)) fun gate_459 =>
    SpreadByteLookup (Plaintext.get (11 : Fin 40)) fun gate_460 =>
    SpreadByteLookup (Plaintext.get (12 : Fin 40)) fun gate_461 =>
    SpreadByteLookup (Plaintext.get (13 : Fin 40)) fun gate_462 =>
    SpreadByteLookup (Plaintext.get (14 : Fin 40)) fun gate_463 =>
    SpreadByteLookup (Plaintext.get (15 : Fin 40)) fun gate_464 =>
    AesRoundColumn_4_4 vec![(gate_439.get (0 : Fin 4)), (gate_448.get (1 : Fin 4)), ((gate_397.get (1 : Fin 2)).get (14 : Fin 240)), (gate_430.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (20 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (21 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (22 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (23 : Fin 240))] fun gate_465 =>
    AesRoundColumn_4_4 vec![(gate_448.get (0 : Fin 4)), ((gate_397.get (1 : Fin 2)).get (13 : Fin 240)), (gate_430.get (2 : Fin 4)), (gate_439.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (24 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (25 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (26 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (27 : Fin 240))] fun gate_466 =>
    AesRoundColumn_4_4 vec![((gate_397.get (1 : Fin 2)).get (12 : Fin 240)), (gate_430.get (1 : Fin 4)), (gate_439.get (2 : Fin 4)), (gate_448.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (28 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (29 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (30 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (31 : Fin 240))] fun gate_467 =>
    ∃gate_468, gate_468 = Gates.mul ((gate_397.get (0 : Fin 2)).get (16 : Fin 240)) (1:F) ∧
    ∃gate_469, gate_469 = Gates.add (0:F) gate_468 ∧
    ∃gate_470, gate_470 = Gates.mul ((gate_397.get (0 : Fin 2)).get (17 : Fin 240)) (1679616:F) ∧
    ∃gate_471, gate_471 = Gates.add gate_469 gate_470 ∧
    ∃gate_472, gate_472 = Gates.mul ((gate_397.get (0 : Fin 2)).get (18 : Fin 240)) (2821109907456:F) ∧
    ∃gate_473, gate_473 = Gates.add gate_471 gate_472 ∧
    ∃gate_474, gate_474 = Gates.mul ((gate_397.get (0 : Fin 2)).get (19 : Fin 240)) (4738381338321616896:F) ∧
    ∃gate_475, gate_475 = Gates.add gate_473 gate_474 ∧
    ∃gate_476, gate_476 = Gates.add (gate_430.get (0 : Fin 4)) (0:F) ∧
    SubstitutionLookup gate_476 fun gate_477 =>
    ∃gate_478, gate_478 = Gates.add gate_475 gate_477 ∧
    ∃gate_479, gate_479 = Gates.add (gate_439.get (1 : Fin 4)) (256:F) ∧
    SubstitutionLookup gate_479 fun gate_480 =>
    ∃gate_481, gate_481 = Gates.add gate_478 gate_480 ∧
    ∃gate_482, gate_482 = Gates.add (gate_448.get (2 : Fin 4)) (512:F) ∧
    SubstitutionLookup gate_482 fun gate_483 =>
    ∃gate_484, gate_484 = Gates.add gate_481 gate_483 ∧
    AesCounterByte_2 ((gate_397.get (0 : Fin 2)).get (15 : Fin 240)) fun gate_485 =>
    ∃gate_486, gate_486 = Gates.add gate_485 (768:F) ∧
    SubstitutionLookup gate_486 fun gate_487 =>
    ∃gate_488, gate_488 = Gates.add gate_484 gate_487 ∧
    AesDecodeWord_4 gate_488 fun gate_489 =>
    AesRoundColumn_4_4 vec![(gate_489.get (0 : Fin 4)), (gate_465.get (1 : Fin 4)), (gate_466.get (2 : Fin 4)), (gate_467.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (32 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (33 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (34 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (35 : Fin 240))] fun gate_490 =>
    AesRoundColumn_4_4 vec![(gate_465.get (0 : Fin 4)), (gate_466.get (1 : Fin 4)), (gate_467.get (2 : Fin 4)), (gate_489.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (36 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (37 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (38 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (39 : Fin 240))] fun gate_491 =>
    AesRoundColumn_4_4 vec![(gate_466.get (0 : Fin 4)), (gate_467.get (1 : Fin 4)), (gate_489.get (2 : Fin 4)), (gate_465.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (40 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (41 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (42 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (43 : Fin 240))] fun gate_492 =>
    AesRoundColumn_4_4 vec![(gate_467.get (0 : Fin 4)), (gate_489.get (1 : Fin 4)), (gate_465.get (2 : Fin 4)), (gate_466.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (44 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (45 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (46 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (47 : Fin 240))] fun gate_493 =>
    AesRoundColumn_4_4 vec![(gate_490.get (0 : Fin 4)), (gate_491.get (1 : Fin 4)), (gate_492.get (2 : Fin 4)), (gate_493.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (48 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (49 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (50 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (51 : Fin 240))] fun gate_494 =>
    AesRoundColumn_4_4 vec![(gate_491.get (0 : Fin 4)), (gate_492.get (1 : Fin 4)), (gate_493.get (2 : Fin 4)), (gate_490.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (52 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (53 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (54 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (55 : Fin 240))] fun gate_495 =>
    AesRoundColumn_4_4 vec![(gate_492.get (0 : Fin 4)), (gate_493.get (1 : Fin 4)), (gate_490.get (2 : Fin 4)), (gate_491.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (56 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (57 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (58 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (59 : Fin 240))] fun gate_496 =>
    AesRoundColumn_4_4 vec![(gate_493.get (0 : Fin 4)), (gate_490.get (1 : Fin 4)), (gate_491.get (2 : Fin 4)), (gate_492.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (60 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (61 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (62 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (63 : Fin 240))] fun gate_497 =>
    AesRoundColumn_4_4 vec![(gate_494.get (0 : Fin 4)), (gate_495.get (1 : Fin 4)), (gate_496.get (2 : Fin 4)), (gate_497.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (64 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (65 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (66 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (67 : Fin 240))] fun gate_498 =>
    AesRoundColumn_4_4 vec![(gate_495.get (0 : Fin 4)), (gate_496.get (1 : Fin 4)), (gate_497.get (2 : Fin 4)), (gate_494.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (68 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (69 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (70 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (71 : Fin 240))] fun gate_499 =>
    AesRoundColumn_4_4 vec![(gate_496.get (0 : Fin 4)), (gate_497.get (1 : Fin 4)), (gate_494.get (2 : Fin 4)), (gate_495.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (72 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (73 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (74 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (75 : Fin 240))] fun gate_500 =>
    AesRoundColumn_4_4 vec![(gate_497.get (0 : Fin 4)), (gate_494.get (1 : Fin 4)), (gate_495.get (2 : Fin 4)), (gate_496.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (76 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (77 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (78 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (79 : Fin 240))] fun gate_501 =>
    AesRoundColumn_4_4 vec![(gate_498.get (0 : Fin 4)), (gate_499.get (1 : Fin 4)), (gate_500.get (2 : Fin 4)), (gate_501.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (80 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (81 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (82 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (83 : Fin 240))] fun gate_502 =>
    AesRoundColumn_4_4 vec![(gate_499.get (0 : Fin 4)), (gate_500.get (1 : Fin 4)), (gate_501.get (2 : Fin 4)), (gate_498.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (84 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (85 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (86 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (87 : Fin 240))] fun gate_503 =>
    AesRoundColumn_4_4 vec![(gate_500.get (0 : Fin 4)), (gate_501.get (1 : Fin 4)), (gate_498.get (2 : Fin 4)), (gate_499.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (88 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (89 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (90 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (91 : Fin 240))] fun gate_504 =>
    AesRoundColumn_4_4 vec![(gate_501.get (0 : Fin 4)), (gate_498.get (1 : Fin 4)), (gate_499.get (2 : Fin 4)), (gate_500.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (92 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (93 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (94 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (95 : Fin 240))] fun gate_505 =>
    AesRoundColumn_4_4 vec![(gate_502.get (0 : Fin 4)), (gate_503.get (1 : Fin 4)), (gate_504.get (2 : Fin 4)), (gate_505.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (96 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (97 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (98 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (99 : Fin 240))] fun gate_506 =>
    AesRoundColumn_4_4 vec![(gate_503.get (0 : Fin 4)), (gate_504.get (1 : Fin 4)), (gate_505.get (2 : Fin 4)), (gate_502.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (100 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (101 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (102 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (103 : Fin 240))] fun gate_507 =>
    AesRoundColumn_4_4 vec![(gate_504.get (0 : Fin 4)), (gate_505.get (1 : Fin 4)), (gate_502.get (2 : Fin 4)), (gate_503.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (104 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (105 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (106 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (107 : Fin 240))] fun gate_508 =>
    AesRoundColumn_4_4 vec![(gate_505.get (0 : Fin 4)), (gate_502.get (1 : Fin 4)), (gate_503.get (2 : Fin 4)), (gate_504.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (108 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (109 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (110 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (111 : Fin 240))] fun gate_509 =>
    AesRoundColumn_4_4 vec![(gate_506.get (0 : Fin 4)), (gate_507.get (1 : Fin 4)), (gate_508.get (2 : Fin 4)), (gate_509.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (112 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (113 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (114 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (115 : Fin 240))] fun gate_510 =>
    AesRoundColumn_4_4 vec![(gate_507.get (0 : Fin 4)), (gate_508.get (1 : Fin 4)), (gate_509.get (2 : Fin 4)), (gate_506.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (116 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (117 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (118 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (119 : Fin 240))] fun gate_511 =>
    AesRoundColumn_4_4 vec![(gate_508.get (0 : Fin 4)), (gate_509.get (1 : Fin 4)), (gate_506.get (2 : Fin 4)), (gate_507.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (120 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (121 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (122 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (123 : Fin 240))] fun gate_512 =>
    AesRoundColumn_4_4 vec![(gate_509.get (0 : Fin 4)), (gate_506.get (1 : Fin 4)), (gate_507.get (2 : Fin 4)), (gate_508.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (124 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (125 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (126 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (127 : Fin 240))] fun gate_513 =>
    AesRoundColumn_4_4 vec![(gate_510.get (0 : Fin 4)), (gate_511.get (1 : Fin 4)), (gate_512.get (2 : Fin 4)), (gate_513.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (128 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (129 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (130 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (131 : Fin 240))] fun gate_514 =>
    AesRoundColumn_4_4 vec![(gate_511.get (0 : Fin 4)), (gate_512.get (1 : Fin 4)), (gate_513.get (2 : Fin 4)), (gate_510.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (132 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (133 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (134 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (135 : Fin 240))] fun gate_515 =>
    AesRoundColumn_4_4 vec![(gate_512.get (0 : Fin 4)), (gate_513.get (1 : Fin 4)), (gate_510.get (2 : Fin 4)), (gate_511.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (136 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (137 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (138 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (139 : Fin 240))] fun gate_516 =>
    AesRoundColumn_4_4 vec![(gate_513.get (0 : Fin 4)), (gate_510.get (1 : Fin 4)), (gate_511.get (2 : Fin 4)), (gate_512.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (140 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (141 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (142 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (143 : Fin 240))] fun gate_517 =>
    AesRoundColumn_4_4 vec![(gate_514.get (0 : Fin 4)), (gate_515.get (1 : Fin 4)), (gate_516.get (2 : Fin 4)), (gate_517.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (144 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (145 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (146 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (147 : Fin 240))] fun gate_518 =>
    AesRoundColumn_4_4 vec![(gate_515.get (0 : Fin 4)), (gate_516.get (1 : Fin 4)), (gate_517.get (2 : Fin 4)), (gate_514.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (148 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (149 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (150 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (151 : Fin 240))] fun gate_519 =>
    AesRoundColumn_4_4 vec![(gate_516.get (0 : Fin 4)), (gate_517.get (1 : Fin 4)), (gate_514.get (2 : Fin 4)), (gate_515.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (152 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (153 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (154 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (155 : Fin 240))] fun gate_520 =>
    AesRoundColumn_4_4 vec![(gate_517.get (0 : Fin 4)), (gate_514.get (1 : Fin 4)), (gate_515.get (2 : Fin 4)), (gate_516.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (156 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (157 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (158 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (159 : Fin 240))] fun gate_521 =>
    AesRoundColumn_4_4 vec![(gate_518.get (0 : Fin 4)), (gate_519.get (1 : Fin 4)), (gate_520.get (2 : Fin 4)), (gate_521.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (160 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (161 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (162 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (163 : Fin 240))] fun gate_522 =>
    AesRoundColumn_4_4 vec![(gate_519.get (0 : Fin 4)), (gate_520.get (1 : Fin 4)), (gate_521.get (2 : Fin 4)), (gate_518.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (164 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (165 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (166 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (167 : Fin 240))] fun gate_523 =>
    AesRoundColumn_4_4 vec![(gate_520.get (0 : Fin 4)), (gate_521.get (1 : Fin 4)), (gate_518.get (2 : Fin 4)), (gate_519.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (168 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (169 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (170 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (171 : Fin 240))] fun gate_524 =>
    AesRoundColumn_4_4 vec![(gate_521.get (0 : Fin 4)), (gate_518.get (1 : Fin 4)), (gate_519.get (2 : Fin 4)), (gate_520.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (172 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (173 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (174 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (175 : Fin 240))] fun gate_525 =>
    AesRoundColumn_4_4 vec![(gate_522.get (0 : Fin 4)), (gate_523.get (1 : Fin 4)), (gate_524.get (2 : Fin 4)), (gate_525.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (176 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (177 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (178 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (179 : Fin 240))] fun gate_526 =>
    AesRoundColumn_4_4 vec![(gate_523.get (0 : Fin 4)), (gate_524.get (1 : Fin 4)), (gate_525.get (2 : Fin 4)), (gate_522.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (180 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (181 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (182 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (183 : Fin 240))] fun gate_527 =>
    AesRoundColumn_4_4 vec![(gate_524.get (0 : Fin 4)), (gate_525.get (1 : Fin 4)), (gate_522.get (2 : Fin 4)), (gate_523.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (184 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (185 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (186 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (187 : Fin 240))] fun gate_528 =>
    AesRoundColumn_4_4 vec![(gate_525.get (0 : Fin 4)), (gate_522.get (1 : Fin 4)), (gate_523.get (2 : Fin 4)), (gate_524.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (188 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (189 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (190 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (191 : Fin 240))] fun gate_529 =>
    AesRoundColumn_4_4 vec![(gate_526.get (0 : Fin 4)), (gate_527.get (1 : Fin 4)), (gate_528.get (2 : Fin 4)), (gate_529.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (192 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (193 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (194 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (195 : Fin 240))] fun gate_530 =>
    AesRoundColumn_4_4 vec![(gate_527.get (0 : Fin 4)), (gate_528.get (1 : Fin 4)), (gate_529.get (2 : Fin 4)), (gate_526.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (196 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (197 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (198 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (199 : Fin 240))] fun gate_531 =>
    AesRoundColumn_4_4 vec![(gate_528.get (0 : Fin 4)), (gate_529.get (1 : Fin 4)), (gate_526.get (2 : Fin 4)), (gate_527.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (200 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (201 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (202 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (203 : Fin 240))] fun gate_532 =>
    AesRoundColumn_4_4 vec![(gate_529.get (0 : Fin 4)), (gate_526.get (1 : Fin 4)), (gate_527.get (2 : Fin 4)), (gate_528.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (204 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (205 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (206 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (207 : Fin 240))] fun gate_533 =>
    AesRoundColumn_4_4 vec![(gate_530.get (0 : Fin 4)), (gate_531.get (1 : Fin 4)), (gate_532.get (2 : Fin 4)), (gate_533.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (208 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (209 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (210 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (211 : Fin 240))] fun gate_534 =>
    AesRoundColumn_4_4 vec![(gate_531.get (0 : Fin 4)), (gate_532.get (1 : Fin 4)), (gate_533.get (2 : Fin 4)), (gate_530.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (212 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (213 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (214 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (215 : Fin 240))] fun gate_535 =>
    AesRoundColumn_4_4 vec![(gate_532.get (0 : Fin 4)), (gate_533.get (1 : Fin 4)), (gate_530.get (2 : Fin 4)), (gate_531.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (216 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (217 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (218 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (219 : Fin 240))] fun gate_536 =>
    AesRoundColumn_4_4 vec![(gate_533.get (0 : Fin 4)), (gate_530.get (1 : Fin 4)), (gate_531.get (2 : Fin 4)), (gate_532.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (220 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (221 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (222 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (223 : Fin 240))] fun gate_537 =>
    AesFinalRound_16_16_16 vec![(gate_534.get (0 : Fin 4)), (gate_534.get (1 : Fin 4)), (gate_534.get (2 : Fin 4)), (gate_534.get (3 : Fin 4)), (gate_535.get (0 : Fin 4)), (gate_535.get (1 : Fin 4)), (gate_535.get (2 : Fin 4)), (gate_535.get (3 : Fin 4)), (gate_536.get (0 : Fin 4)), (gate_536.get (1 : Fin 4)), (gate_536.get (2 : Fin 4)), (gate_536.get (3 : Fin 4)), (gate_537.get (0 : Fin 4)), (gate_537.get (1 : Fin 4)), (gate_537.get (2 : Fin 4)), (gate_537.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (224 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (225 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (226 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (227 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (228 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (229 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (230 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (231 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (232 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (233 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (234 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (235 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (236 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (237 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (238 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (239 : Fin 240))] vec![gate_449, gate_450, gate_451, gate_452, gate_453, gate_454, gate_455, gate_456, gate_457, gate_458, gate_459, gate_460, gate_461, gate_462, gate_463, gate_464] fun gate_538 =>
    SpreadByteLookup (Plaintext.get (16 : Fin 40)) fun gate_539 =>
    SpreadByteLookup (Plaintext.get (17 : Fin 40)) fun gate_540 =>
    SpreadByteLookup (Plaintext.get (18 : Fin 40)) fun gate_541 =>
    SpreadByteLookup (Plaintext.get (19 : Fin 40)) fun gate_542 =>
    SpreadByteLookup (Plaintext.get (20 : Fin 40)) fun gate_543 =>
    SpreadByteLookup (Plaintext.get (21 : Fin 40)) fun gate_544 =>
    SpreadByteLookup (Plaintext.get (22 : Fin 40)) fun gate_545 =>
    SpreadByteLookup (Plaintext.get (23 : Fin 40)) fun gate_546 =>
    SpreadByteLookup (Plaintext.get (24 : Fin 40)) fun gate_547 =>
    SpreadByteLookup (Plaintext.get (25 : Fin 40)) fun gate_548 =>
    SpreadByteLookup (Plaintext.get (26 : Fin 40)) fun gate_549 =>
    SpreadByteLookup (Plaintext.get (27 : Fin 40)) fun gate_550 =>
    SpreadByteLookup (Plaintext.get (28 : Fin 40)) fun gate_551 =>
    SpreadByteLookup (Plaintext.get (29 : Fin 40)) fun gate_552 =>
    SpreadByteLookup (Plaintext.get (30 : Fin 40)) fun gate_553 =>
    SpreadByteLookup (Plaintext.get (31 : Fin 40)) fun gate_554 =>
    AesCounterByte_3 ((gate_397.get (0 : Fin 2)).get (15 : Fin 240)) fun gate_555 =>
    ∃gate_556, gate_556 = Gates.add gate_555 (768:F) ∧
    SubstitutionLookup gate_556 fun gate_557 =>
    ∃gate_558, gate_558 = Gates.add gate_484 gate_557 ∧
    AesDecodeWord_4 gate_558 fun gate_559 =>
    AesRoundColumn_4_4 vec![(gate_559.get (0 : Fin 4)), (gate_465.get (1 : Fin 4)), (gate_466.get (2 : Fin 4)), (gate_467.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (32 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (33 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (34 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (35 : Fin 240))] fun gate_560 =>
    AesRoundColumn_4_4 vec![(gate_465.get (0 : Fin 4)), (gate_466.get (1 : Fin 4)), (gate_467.get (2 : Fin 4)), (gate_559.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (36 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (37 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (38 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (39 : Fin 240))] fun gate_561 =>
    AesRoundColumn_4_4 vec![(gate_466.get (0 : Fin 4)), (gate_467.get (1 : Fin 4)), (gate_559.get (2 : Fin 4)), (gate_465.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (40 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (41 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (42 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (43 : Fin 240))] fun gate_562 =>
    AesRoundColumn_4_4 vec![(gate_467.get (0 : Fin 4)), (gate_559.get (1 : Fin 4)), (gate_465.get (2 : Fin 4)), (gate_466.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (44 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (45 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (46 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (47 : Fin 240))] fun gate_563 =>
    AesRoundColumn_4_4 vec![(gate_560.get (0 : Fin 4)), (gate_561.get (1 : Fin 4)), (gate_562.get (2 : Fin 4)), (gate_563.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (48 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (49 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (50 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (51 : Fin 240))] fun gate_564 =>
    AesRoundColumn_4_4 vec![(gate_561.get (0 : Fin 4)), (gate_562.get (1 : Fin 4)), (gate_563.get (2 : Fin 4)), (gate_560.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (52 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (53 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (54 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (55 : Fin 240))] fun gate_565 =>
    AesRoundColumn_4_4 vec![(gate_562.get (0 : Fin 4)), (gate_563.get (1 : Fin 4)), (gate_560.get (2 : Fin 4)), (gate_561.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (56 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (57 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (58 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (59 : Fin 240))] fun gate_566 =>
    AesRoundColumn_4_4 vec![(gate_563.get (0 : Fin 4)), (gate_560.get (1 : Fin 4)), (gate_561.get (2 : Fin 4)), (gate_562.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (60 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (61 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (62 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (63 : Fin 240))] fun gate_567 =>
    AesRoundColumn_4_4 vec![(gate_564.get (0 : Fin 4)), (gate_565.get (1 : Fin 4)), (gate_566.get (2 : Fin 4)), (gate_567.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (64 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (65 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (66 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (67 : Fin 240))] fun gate_568 =>
    AesRoundColumn_4_4 vec![(gate_565.get (0 : Fin 4)), (gate_566.get (1 : Fin 4)), (gate_567.get (2 : Fin 4)), (gate_564.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (68 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (69 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (70 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (71 : Fin 240))] fun gate_569 =>
    AesRoundColumn_4_4 vec![(gate_566.get (0 : Fin 4)), (gate_567.get (1 : Fin 4)), (gate_564.get (2 : Fin 4)), (gate_565.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (72 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (73 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (74 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (75 : Fin 240))] fun gate_570 =>
    AesRoundColumn_4_4 vec![(gate_567.get (0 : Fin 4)), (gate_564.get (1 : Fin 4)), (gate_565.get (2 : Fin 4)), (gate_566.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (76 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (77 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (78 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (79 : Fin 240))] fun gate_571 =>
    AesRoundColumn_4_4 vec![(gate_568.get (0 : Fin 4)), (gate_569.get (1 : Fin 4)), (gate_570.get (2 : Fin 4)), (gate_571.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (80 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (81 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (82 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (83 : Fin 240))] fun gate_572 =>
    AesRoundColumn_4_4 vec![(gate_569.get (0 : Fin 4)), (gate_570.get (1 : Fin 4)), (gate_571.get (2 : Fin 4)), (gate_568.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (84 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (85 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (86 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (87 : Fin 240))] fun gate_573 =>
    AesRoundColumn_4_4 vec![(gate_570.get (0 : Fin 4)), (gate_571.get (1 : Fin 4)), (gate_568.get (2 : Fin 4)), (gate_569.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (88 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (89 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (90 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (91 : Fin 240))] fun gate_574 =>
    AesRoundColumn_4_4 vec![(gate_571.get (0 : Fin 4)), (gate_568.get (1 : Fin 4)), (gate_569.get (2 : Fin 4)), (gate_570.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (92 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (93 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (94 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (95 : Fin 240))] fun gate_575 =>
    AesRoundColumn_4_4 vec![(gate_572.get (0 : Fin 4)), (gate_573.get (1 : Fin 4)), (gate_574.get (2 : Fin 4)), (gate_575.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (96 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (97 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (98 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (99 : Fin 240))] fun gate_576 =>
    AesRoundColumn_4_4 vec![(gate_573.get (0 : Fin 4)), (gate_574.get (1 : Fin 4)), (gate_575.get (2 : Fin 4)), (gate_572.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (100 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (101 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (102 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (103 : Fin 240))] fun gate_577 =>
    AesRoundColumn_4_4 vec![(gate_574.get (0 : Fin 4)), (gate_575.get (1 : Fin 4)), (gate_572.get (2 : Fin 4)), (gate_573.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (104 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (105 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (106 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (107 : Fin 240))] fun gate_578 =>
    AesRoundColumn_4_4 vec![(gate_575.get (0 : Fin 4)), (gate_572.get (1 : Fin 4)), (gate_573.get (2 : Fin 4)), (gate_574.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (108 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (109 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (110 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (111 : Fin 240))] fun gate_579 =>
    AesRoundColumn_4_4 vec![(gate_576.get (0 : Fin 4)), (gate_577.get (1 : Fin 4)), (gate_578.get (2 : Fin 4)), (gate_579.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (112 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (113 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (114 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (115 : Fin 240))] fun gate_580 =>
    AesRoundColumn_4_4 vec![(gate_577.get (0 : Fin 4)), (gate_578.get (1 : Fin 4)), (gate_579.get (2 : Fin 4)), (gate_576.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (116 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (117 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (118 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (119 : Fin 240))] fun gate_581 =>
    AesRoundColumn_4_4 vec![(gate_578.get (0 : Fin 4)), (gate_579.get (1 : Fin 4)), (gate_576.get (2 : Fin 4)), (gate_577.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (120 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (121 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (122 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (123 : Fin 240))] fun gate_582 =>
    AesRoundColumn_4_4 vec![(gate_579.get (0 : Fin 4)), (gate_576.get (1 : Fin 4)), (gate_577.get (2 : Fin 4)), (gate_578.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (124 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (125 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (126 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (127 : Fin 240))] fun gate_583 =>
    AesRoundColumn_4_4 vec![(gate_580.get (0 : Fin 4)), (gate_581.get (1 : Fin 4)), (gate_582.get (2 : Fin 4)), (gate_583.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (128 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (129 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (130 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (131 : Fin 240))] fun gate_584 =>
    AesRoundColumn_4_4 vec![(gate_581.get (0 : Fin 4)), (gate_582.get (1 : Fin 4)), (gate_583.get (2 : Fin 4)), (gate_580.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (132 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (133 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (134 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (135 : Fin 240))] fun gate_585 =>
    AesRoundColumn_4_4 vec![(gate_582.get (0 : Fin 4)), (gate_583.get (1 : Fin 4)), (gate_580.get (2 : Fin 4)), (gate_581.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (136 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (137 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (138 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (139 : Fin 240))] fun gate_586 =>
    AesRoundColumn_4_4 vec![(gate_583.get (0 : Fin 4)), (gate_580.get (1 : Fin 4)), (gate_581.get (2 : Fin 4)), (gate_582.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (140 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (141 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (142 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (143 : Fin 240))] fun gate_587 =>
    AesRoundColumn_4_4 vec![(gate_584.get (0 : Fin 4)), (gate_585.get (1 : Fin 4)), (gate_586.get (2 : Fin 4)), (gate_587.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (144 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (145 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (146 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (147 : Fin 240))] fun gate_588 =>
    AesRoundColumn_4_4 vec![(gate_585.get (0 : Fin 4)), (gate_586.get (1 : Fin 4)), (gate_587.get (2 : Fin 4)), (gate_584.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (148 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (149 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (150 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (151 : Fin 240))] fun gate_589 =>
    AesRoundColumn_4_4 vec![(gate_586.get (0 : Fin 4)), (gate_587.get (1 : Fin 4)), (gate_584.get (2 : Fin 4)), (gate_585.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (152 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (153 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (154 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (155 : Fin 240))] fun gate_590 =>
    AesRoundColumn_4_4 vec![(gate_587.get (0 : Fin 4)), (gate_584.get (1 : Fin 4)), (gate_585.get (2 : Fin 4)), (gate_586.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (156 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (157 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (158 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (159 : Fin 240))] fun gate_591 =>
    AesRoundColumn_4_4 vec![(gate_588.get (0 : Fin 4)), (gate_589.get (1 : Fin 4)), (gate_590.get (2 : Fin 4)), (gate_591.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (160 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (161 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (162 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (163 : Fin 240))] fun gate_592 =>
    AesRoundColumn_4_4 vec![(gate_589.get (0 : Fin 4)), (gate_590.get (1 : Fin 4)), (gate_591.get (2 : Fin 4)), (gate_588.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (164 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (165 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (166 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (167 : Fin 240))] fun gate_593 =>
    AesRoundColumn_4_4 vec![(gate_590.get (0 : Fin 4)), (gate_591.get (1 : Fin 4)), (gate_588.get (2 : Fin 4)), (gate_589.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (168 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (169 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (170 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (171 : Fin 240))] fun gate_594 =>
    AesRoundColumn_4_4 vec![(gate_591.get (0 : Fin 4)), (gate_588.get (1 : Fin 4)), (gate_589.get (2 : Fin 4)), (gate_590.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (172 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (173 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (174 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (175 : Fin 240))] fun gate_595 =>
    AesRoundColumn_4_4 vec![(gate_592.get (0 : Fin 4)), (gate_593.get (1 : Fin 4)), (gate_594.get (2 : Fin 4)), (gate_595.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (176 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (177 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (178 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (179 : Fin 240))] fun gate_596 =>
    AesRoundColumn_4_4 vec![(gate_593.get (0 : Fin 4)), (gate_594.get (1 : Fin 4)), (gate_595.get (2 : Fin 4)), (gate_592.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (180 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (181 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (182 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (183 : Fin 240))] fun gate_597 =>
    AesRoundColumn_4_4 vec![(gate_594.get (0 : Fin 4)), (gate_595.get (1 : Fin 4)), (gate_592.get (2 : Fin 4)), (gate_593.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (184 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (185 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (186 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (187 : Fin 240))] fun gate_598 =>
    AesRoundColumn_4_4 vec![(gate_595.get (0 : Fin 4)), (gate_592.get (1 : Fin 4)), (gate_593.get (2 : Fin 4)), (gate_594.get (3 : Fin 4))] vec![((gate_397.get (0 : Fin 2)).get (188 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (189 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (190 : Fin 240)), ((gate_397.get (0 : Fin 2)).get (191 : Fin 240))] fun gate_599 =>
    EnvelopeMerge_32_65_40_4_p3 EphemeralSk RecipientPk Plaintext Context Elements Blinding gate_259 gate_263 gate_364 gate_381 gate_397 gate_465 gate_466 gate_467 gate_484 gate_538 gate_539 gate_540 gate_541 gate_542 gate_543 gate_544 gate_545 gate_546 gate_547 gate_548 gate_549 gate_550 gate_551 gate_552 gate_553 gate_554 gate_596 gate_597 gate_598 gate_599

def EnvelopeMerge_32_65_40_4_p1 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Plaintext: List.Vector F 40) (Context: F) (Elements: List.Vector F 4) (Blinding: F) (gate_72: F) (gate_80: F) (gate_88: F) (gate_96: F) (gate_104: F) (gate_112: F) (gate_120: F) (gate_128: F) (gate_136: F) (gate_144: F) (gate_152: F) (gate_160: F) (gate_168: F) (gate_176: F) (gate_184: F) (gate_192: F) (gate_198: F) (gate_199: F): Prop :=
    ∃gate_200, gate_200 = Gates.add gate_199 (RecipientPk.get (1 : Fin 65)) ∧
    ∃gate_201, gate_201 = Gates.mul gate_200 (256:F) ∧
    ∃gate_202, gate_202 = Gates.add gate_201 (RecipientPk.get (2 : Fin 65)) ∧
    ∃gate_203, gate_203 = Gates.mul gate_202 (256:F) ∧
    ∃gate_204, gate_204 = Gates.add gate_203 (RecipientPk.get (3 : Fin 65)) ∧
    ∃gate_205, gate_205 = Gates.mul gate_204 (256:F) ∧
    ∃gate_206, gate_206 = Gates.add gate_205 (RecipientPk.get (4 : Fin 65)) ∧
    ∃gate_207, gate_207 = Gates.mul gate_206 (256:F) ∧
    ∃gate_208, gate_208 = Gates.add gate_207 (RecipientPk.get (5 : Fin 65)) ∧
    ∃gate_209, gate_209 = Gates.mul gate_208 (256:F) ∧
    ∃gate_210, gate_210 = Gates.add gate_209 (RecipientPk.get (6 : Fin 65)) ∧
    ∃gate_211, gate_211 = Gates.mul gate_210 (256:F) ∧
    ∃gate_212, gate_212 = Gates.add gate_211 (RecipientPk.get (7 : Fin 65)) ∧
    ∃gate_213, gate_213 = Gates.mul gate_212 (256:F) ∧
    ∃gate_214, gate_214 = Gates.add gate_213 (RecipientPk.get (8 : Fin 65)) ∧
    ∃gate_215, gate_215 = Gates.mul gate_214 (256:F) ∧
    ∃gate_216, gate_216 = Gates.add gate_215 (RecipientPk.get (9 : Fin 65)) ∧
    ∃gate_217, gate_217 = Gates.mul gate_216 (256:F) ∧
    ∃gate_218, gate_218 = Gates.add gate_217 (RecipientPk.get (10 : Fin 65)) ∧
    ∃gate_219, gate_219 = Gates.mul gate_218 (256:F) ∧
    ∃gate_220, gate_220 = Gates.add gate_219 (RecipientPk.get (11 : Fin 65)) ∧
    ∃gate_221, gate_221 = Gates.mul gate_220 (256:F) ∧
    ∃gate_222, gate_222 = Gates.add gate_221 (RecipientPk.get (12 : Fin 65)) ∧
    ∃gate_223, gate_223 = Gates.mul gate_222 (256:F) ∧
    ∃gate_224, gate_224 = Gates.add gate_223 (RecipientPk.get (13 : Fin 65)) ∧
    ∃gate_225, gate_225 = Gates.mul gate_224 (256:F) ∧
    ∃gate_226, gate_226 = Gates.add gate_225 (RecipientPk.get (14 : Fin 65)) ∧
    ∃gate_227, gate_227 = Gates.mul gate_226 (256:F) ∧
    ∃gate_228, gate_228 = Gates.add gate_227 (RecipientPk.get (15 : Fin 65)) ∧
    ∃gate_229, gate_229 = Gates.mul gate_228 (256:F) ∧
    ∃gate_230, gate_230 = Gates.add gate_229 (RecipientPk.get (16 : Fin 65)) ∧
    ∃gate_231, gate_231 = Gates.mul gate_230 (256:F) ∧
    ∃gate_232, gate_232 = Gates.add gate_231 (RecipientPk.get (17 : Fin 65)) ∧
    ∃gate_233, gate_233 = Gates.mul gate_232 (256:F) ∧
    ∃gate_234, gate_234 = Gates.add gate_233 (RecipientPk.get (18 : Fin 65)) ∧
    ∃gate_235, gate_235 = Gates.mul gate_234 (256:F) ∧
    ∃gate_236, gate_236 = Gates.add gate_235 (RecipientPk.get (19 : Fin 65)) ∧
    ∃gate_237, gate_237 = Gates.mul gate_236 (256:F) ∧
    ∃gate_238, gate_238 = Gates.add gate_237 (RecipientPk.get (20 : Fin 65)) ∧
    ∃gate_239, gate_239 = Gates.mul gate_238 (256:F) ∧
    ∃gate_240, gate_240 = Gates.add gate_239 (RecipientPk.get (21 : Fin 65)) ∧
    ∃gate_241, gate_241 = Gates.mul gate_240 (256:F) ∧
    ∃gate_242, gate_242 = Gates.add gate_241 (RecipientPk.get (22 : Fin 65)) ∧
    ∃gate_243, gate_243 = Gates.mul gate_242 (256:F) ∧
    ∃gate_244, gate_244 = Gates.add gate_243 (RecipientPk.get (23 : Fin 65)) ∧
    ∃gate_245, gate_245 = Gates.mul gate_244 (256:F) ∧
    ∃gate_246, gate_246 = Gates.add gate_245 (RecipientPk.get (24 : Fin 65)) ∧
    ∃gate_247, gate_247 = Gates.mul gate_246 (256:F) ∧
    ∃gate_248, gate_248 = Gates.add gate_247 (RecipientPk.get (25 : Fin 65)) ∧
    ∃gate_249, gate_249 = Gates.mul gate_248 (256:F) ∧
    ∃gate_250, gate_250 = Gates.add gate_249 (RecipientPk.get (26 : Fin 65)) ∧
    ∃gate_251, gate_251 = Gates.mul gate_250 (256:F) ∧
    ∃gate_252, gate_252 = Gates.add gate_251 (RecipientPk.get (27 : Fin 65)) ∧
    ∃gate_253, gate_253 = Gates.mul gate_252 (256:F) ∧
    ∃gate_254, gate_254 = Gates.add gate_253 (RecipientPk.get (28 : Fin 65)) ∧
    ∃gate_255, gate_255 = Gates.mul gate_254 (256:F) ∧
    ∃gate_256, gate_256 = Gates.add gate_255 (RecipientPk.get (29 : Fin 65)) ∧
    ∃gate_257, gate_257 = Gates.mul gate_256 (256:F) ∧
    ∃gate_258, gate_258 = Gates.add gate_257 (RecipientPk.get (30 : Fin 65)) ∧
    ∃gate_259, gate_259 = Gates.add gate_198 gate_258 ∧
    ∃gate_260, gate_260 = Gates.mul (0:F) (256:F) ∧
    ∃gate_261, gate_261 = Gates.add gate_260 (RecipientPk.get (31 : Fin 65)) ∧
    ∃gate_262, gate_262 = Gates.mul gate_261 (256:F) ∧
    ∃gate_263, gate_263 = Gates.add gate_262 (RecipientPk.get (32 : Fin 65)) ∧
    RangeCheck 8 (EphemeralSk.get (0 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (1 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (2 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (3 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (4 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (5 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (6 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (7 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (8 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (9 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (10 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (11 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (12 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (13 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (14 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (15 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (16 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (17 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (18 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (19 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (20 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (21 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (22 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (23 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (24 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (25 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (26 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (27 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (28 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (29 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (30 : Fin 32)) ∧
    RangeCheck 8 (EphemeralSk.get (31 : Fin 32)) ∧
    ∃gate_296, gate_296 = Gates.mul (0:F) (256:F) ∧
    ∃gate_297, gate_297 = Gates.add gate_296 (EphemeralSk.get (28 : Fin 32)) ∧
    ∃gate_298, gate_298 = Gates.mul gate_297 (256:F) ∧
    ∃gate_299, gate_299 = Gates.add gate_298 (EphemeralSk.get (29 : Fin 32)) ∧
    ∃gate_300, gate_300 = Gates.mul gate_299 (256:F) ∧
    ∃gate_301, gate_301 = Gates.add gate_300 (EphemeralSk.get (30 : Fin 32)) ∧
    ∃gate_302, gate_302 = Gates.mul gate_301 (256:F) ∧
    ∃gate_303, gate_303 = Gates.add gate_302 (EphemeralSk.get (31 : Fin 32)) ∧
    ∃gate_304, gate_304 = Gates.mul (0:F) (256:F) ∧
    ∃gate_305, gate_305 = Gates.add gate_304 (EphemeralSk.get (24 : Fin 32)) ∧
    ∃gate_306, gate_306 = Gates.mul gate_305 (256:F) ∧
    ∃gate_307, gate_307 = Gates.add gate_306 (EphemeralSk.get (25 : Fin 32)) ∧
    ∃gate_308, gate_308 = Gates.mul gate_307 (256:F) ∧
    ∃gate_309, gate_309 = Gates.add gate_308 (EphemeralSk.get (26 : Fin 32)) ∧
    ∃gate_310, gate_310 = Gates.mul gate_309 (256:F) ∧
    ∃gate_311, gate_311 = Gates.add gate_310 (EphemeralSk.get (27 : Fin 32)) ∧
    ∃gate_312, gate_312 = Gates.mul (0:F) (256:F) ∧
    ∃gate_313, gate_313 = Gates.add gate_312 (EphemeralSk.get (20 : Fin 32)) ∧
    ∃gate_314, gate_314 = Gates.mul gate_313 (256:F) ∧
    ∃gate_315, gate_315 = Gates.add gate_314 (EphemeralSk.get (21 : Fin 32)) ∧
    ∃gate_316, gate_316 = Gates.mul gate_315 (256:F) ∧
    ∃gate_317, gate_317 = Gates.add gate_316 (EphemeralSk.get (22 : Fin 32)) ∧
    ∃gate_318, gate_318 = Gates.mul gate_317 (256:F) ∧
    ∃gate_319, gate_319 = Gates.add gate_318 (EphemeralSk.get (23 : Fin 32)) ∧
    ∃gate_320, gate_320 = Gates.mul (0:F) (256:F) ∧
    ∃gate_321, gate_321 = Gates.add gate_320 (EphemeralSk.get (16 : Fin 32)) ∧
    ∃gate_322, gate_322 = Gates.mul gate_321 (256:F) ∧
    ∃gate_323, gate_323 = Gates.add gate_322 (EphemeralSk.get (17 : Fin 32)) ∧
    ∃gate_324, gate_324 = Gates.mul gate_323 (256:F) ∧
    ∃gate_325, gate_325 = Gates.add gate_324 (EphemeralSk.get (18 : Fin 32)) ∧
    ∃gate_326, gate_326 = Gates.mul gate_325 (256:F) ∧
    ∃gate_327, gate_327 = Gates.add gate_326 (EphemeralSk.get (19 : Fin 32)) ∧
    ∃gate_328, gate_328 = Gates.mul (0:F) (256:F) ∧
    ∃gate_329, gate_329 = Gates.add gate_328 (EphemeralSk.get (12 : Fin 32)) ∧
    ∃gate_330, gate_330 = Gates.mul gate_329 (256:F) ∧
    ∃gate_331, gate_331 = Gates.add gate_330 (EphemeralSk.get (13 : Fin 32)) ∧
    ∃gate_332, gate_332 = Gates.mul gate_331 (256:F) ∧
    ∃gate_333, gate_333 = Gates.add gate_332 (EphemeralSk.get (14 : Fin 32)) ∧
    ∃gate_334, gate_334 = Gates.mul gate_333 (256:F) ∧
    ∃gate_335, gate_335 = Gates.add gate_334 (EphemeralSk.get (15 : Fin 32)) ∧
    ∃gate_336, gate_336 = Gates.mul (0:F) (256:F) ∧
    ∃gate_337, gate_337 = Gates.add gate_336 (EphemeralSk.get (8 : Fin 32)) ∧
    ∃gate_338, gate_338 = Gates.mul gate_337 (256:F) ∧
    ∃gate_339, gate_339 = Gates.add gate_338 (EphemeralSk.get (9 : Fin 32)) ∧
    ∃gate_340, gate_340 = Gates.mul gate_339 (256:F) ∧
    ∃gate_341, gate_341 = Gates.add gate_340 (EphemeralSk.get (10 : Fin 32)) ∧
    ∃gate_342, gate_342 = Gates.mul gate_341 (256:F) ∧
    ∃gate_343, gate_343 = Gates.add gate_342 (EphemeralSk.get (11 : Fin 32)) ∧
    ∃gate_344, gate_344 = Gates.mul (0:F) (256:F) ∧
    ∃gate_345, gate_345 = Gates.add gate_344 (EphemeralSk.get (4 : Fin 32)) ∧
    ∃gate_346, gate_346 = Gates.mul gate_345 (256:F) ∧
    ∃gate_347, gate_347 = Gates.add gate_346 (EphemeralSk.get (5 : Fin 32)) ∧
    ∃gate_348, gate_348 = Gates.mul gate_347 (256:F) ∧
    ∃gate_349, gate_349 = Gates.add gate_348 (EphemeralSk.get (6 : Fin 32)) ∧
    ∃gate_350, gate_350 = Gates.mul gate_349 (256:F) ∧
    ∃gate_351, gate_351 = Gates.add gate_350 (EphemeralSk.get (7 : Fin 32)) ∧
    ∃gate_352, gate_352 = Gates.mul (0:F) (256:F) ∧
    ∃gate_353, gate_353 = Gates.add gate_352 (EphemeralSk.get (0 : Fin 32)) ∧
    ∃gate_354, gate_354 = Gates.mul gate_353 (256:F) ∧
    ∃gate_355, gate_355 = Gates.add gate_354 (EphemeralSk.get (1 : Fin 32)) ∧
    ∃gate_356, gate_356 = Gates.mul gate_355 (256:F) ∧
    ∃gate_357, gate_357 = Gates.add gate_356 (EphemeralSk.get (2 : Fin 32)) ∧
    ∃gate_358, gate_358 = Gates.mul gate_357 (256:F) ∧
    ∃gate_359, gate_359 = Gates.add gate_358 (EphemeralSk.get (3 : Fin 32)) ∧
    ScalarMulChecked_8_8_8_h9a706aba vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] vec![gate_303, gate_311, gate_319, gate_327, gate_335, gate_343, gate_351, gate_359] fun gate_360 =>
    ScalarMulBase_8_h3037b025 vec![gate_303, gate_311, gate_319, gate_327, gate_335, gate_343, gate_351, gate_359] fun gate_361 =>
    AssertCanonical_8_0_hcc2f8a19 (gate_361.get (0 : Fin 2)) ∧
    AssertCanonical_8_0_hcc2f8a19 (gate_361.get (1 : Fin 2)) ∧
    CompressedPacking_8_8_32 (gate_361.get (0 : Fin 2)) (gate_361.get (1 : Fin 2)) fun gate_364 =>
    AssertCanonical_8_0_hcc2f8a19 (gate_360.get (0 : Fin 2)) ∧
    SplitLowBits_8_32 ((gate_360.get (0 : Fin 2)).get (0 : Fin 8)) fun gate_366 =>
    ∃gate_367, gate_367 = Gates.mul ((gate_360.get (0 : Fin 2)).get (1 : Fin 8)) (16777216:F) ∧
    ∃gate_368, gate_368 = Gates.add (gate_366.get (0 : Fin 2)) gate_367 ∧
    ∃gate_369, gate_369 = Gates.mul ((gate_360.get (0 : Fin 2)).get (2 : Fin 8)) (72057594037927936:F) ∧
    ∃gate_370, gate_370 = Gates.add gate_368 gate_369 ∧
    ∃gate_371, gate_371 = Gates.mul ((gate_360.get (0 : Fin 2)).get (3 : Fin 8)) K_1 ∧
    ∃gate_372, gate_372 = Gates.add gate_370 gate_371 ∧
    ∃gate_373, gate_373 = Gates.mul ((gate_360.get (0 : Fin 2)).get (4 : Fin 8)) K_2 ∧
    ∃gate_374, gate_374 = Gates.add gate_372 gate_373 ∧
    ∃gate_375, gate_375 = Gates.mul ((gate_360.get (0 : Fin 2)).get (5 : Fin 8)) K_3 ∧
    ∃gate_376, gate_376 = Gates.add gate_374 gate_375 ∧
    ∃gate_377, gate_377 = Gates.mul ((gate_360.get (0 : Fin 2)).get (6 : Fin 8)) K_4 ∧
    ∃gate_378, gate_378 = Gates.add gate_376 gate_377 ∧
    ∃gate_379, gate_379 = Gates.mul ((gate_360.get (0 : Fin 2)).get (7 : Fin 8)) K_5 ∧
    ∃gate_380, gate_380 = Gates.add gate_378 gate_379 ∧
    Poseidon_8 vec![(1414350163:F), gate_380, (gate_366.get (1 : Fin 2)), (gate_364.get (0 : Fin 2)), (gate_364.get (1 : Fin 2)), gate_259, gate_263, Context] (0:F) fun gate_381 =>
    ∃gate_382, gate_382 = Gates.mul (0:F) (256:F) ∧
    ∃gate_383, gate_383 = Gates.add gate_382 (84:F) ∧
    ∃gate_384, gate_384 = Gates.mul gate_383 (256:F) ∧
    ∃gate_385, gate_385 = Gates.add gate_384 (77:F) ∧
    ∃gate_386, gate_386 = Gates.mul gate_385 (256:F) ∧
    ∃gate_387, gate_387 = Gates.add gate_386 (69:F) ∧
    ∃gate_388, gate_388 = Gates.mul gate_387 (256:F) ∧
    ∃gate_389, gate_389 = Gates.add gate_388 (67:F) ∧
    Poseidon_3 vec![(1414353737:F), gate_381, gate_389] (0:F) fun gate_390 =>
    Poseidon_2 vec![(1414353739:F), gate_390] (0:F) fun gate_391 =>
    Poseidon_2 vec![(1414353740:F), gate_390] (0:F) fun gate_392 =>
    FieldBytesBE_32 gate_391 fun gate_393 =>
    FieldBytesBE_32 gate_392 fun gate_394 =>
    Poseidon_2 vec![(1414353742:F), gate_390] (0:F) fun gate_395 =>
    FieldBytesBE_32 gate_395 fun gate_396 =>
    AesKeyExpansion_32 vec![(gate_394.get (16 : Fin 32)), (gate_394.get (17 : Fin 32)), (gate_394.get (18 : Fin 32)), (gate_394.get (19 : Fin 32)), (gate_394.get (20 : Fin 32)), (gate_394.get (21 : Fin 32)), (gate_394.get (22 : Fin 32)), (gate_394.get (23 : Fin 32)), (gate_394.get (24 : Fin 32)), (gate_394.get (25 : Fin 32)), (gate_394.get (26 : Fin 32)), (gate_394.get (27 : Fin 32)), (gate_394.get (28 : Fin 32)), (gate_394.get (29 : Fin 32)), (gate_394.get (30 : Fin 32)), (gate_394.get (31 : Fin 32)), (gate_393.get (16 : Fin 32)), (gate_393.get (17 : Fin 32)), (gate_393.get (18 : Fin 32)), (gate_393.get (19 : Fin 32)), (gate_393.get (20 : Fin 32)), (gate_393.get (21 : Fin 32)), (gate_393.get (22 : Fin 32)), (gate_393.get (23 : Fin 32)), (gate_393.get (24 : Fin 32)), (gate_393.get (25 : Fin 32)), (gate_393.get (26 : Fin 32)), (gate_393.get (27 : Fin 32)), (gate_393.get (28 : Fin 32)), (gate_393.get (29 : Fin 32)), (gate_393.get (30 : Fin 32)), (gate_393.get (31 : Fin 32))] fun gate_397 =>
    SpreadByteLookup (gate_396.get (20 : Fin 32)) fun gate_398 =>
    SpreadByteLookup (gate_396.get (21 : Fin 32)) fun gate_399 =>
    EnvelopeMerge_32_65_40_4_p2 EphemeralSk RecipientPk Plaintext Context Elements Blinding gate_259 gate_263 gate_364 gate_381 gate_396 gate_397 gate_398 gate_399

def EnvelopeMerge_32_65_40_4 (EphemeralSk: List.Vector F 32) (RecipientPk: List.Vector F 65) (Plaintext: List.Vector F 40) (Context: F) (Elements: List.Vector F 4) (Blinding: F): Prop :=
    Gates.eq (RecipientPk.get (0 : Fin 65)) (4:F) ∧
    RangeCheck 8 (RecipientPk.get (1 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (2 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (3 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (4 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (5 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (6 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (7 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (8 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (9 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (10 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (11 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (12 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (13 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (14 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (15 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (16 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (17 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (18 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (19 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (20 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (21 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (22 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (23 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (24 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (25 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (26 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (27 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (28 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (29 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (30 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (31 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (32 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (33 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (34 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (35 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (36 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (37 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (38 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (39 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (40 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (41 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (42 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (43 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (44 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (45 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (46 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (47 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (48 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (49 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (50 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (51 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (52 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (53 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (54 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (55 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (56 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (57 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (58 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (59 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (60 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (61 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (62 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (63 : Fin 65)) ∧
    RangeCheck 8 (RecipientPk.get (64 : Fin 65)) ∧
    ∃gate_65, gate_65 = Gates.mul (0:F) (256:F) ∧
    ∃gate_66, gate_66 = Gates.add gate_65 (RecipientPk.get (29 : Fin 65)) ∧
    ∃gate_67, gate_67 = Gates.mul gate_66 (256:F) ∧
    ∃gate_68, gate_68 = Gates.add gate_67 (RecipientPk.get (30 : Fin 65)) ∧
    ∃gate_69, gate_69 = Gates.mul gate_68 (256:F) ∧
    ∃gate_70, gate_70 = Gates.add gate_69 (RecipientPk.get (31 : Fin 65)) ∧
    ∃gate_71, gate_71 = Gates.mul gate_70 (256:F) ∧
    ∃gate_72, gate_72 = Gates.add gate_71 (RecipientPk.get (32 : Fin 65)) ∧
    ∃gate_73, gate_73 = Gates.mul (0:F) (256:F) ∧
    ∃gate_74, gate_74 = Gates.add gate_73 (RecipientPk.get (25 : Fin 65)) ∧
    ∃gate_75, gate_75 = Gates.mul gate_74 (256:F) ∧
    ∃gate_76, gate_76 = Gates.add gate_75 (RecipientPk.get (26 : Fin 65)) ∧
    ∃gate_77, gate_77 = Gates.mul gate_76 (256:F) ∧
    ∃gate_78, gate_78 = Gates.add gate_77 (RecipientPk.get (27 : Fin 65)) ∧
    ∃gate_79, gate_79 = Gates.mul gate_78 (256:F) ∧
    ∃gate_80, gate_80 = Gates.add gate_79 (RecipientPk.get (28 : Fin 65)) ∧
    ∃gate_81, gate_81 = Gates.mul (0:F) (256:F) ∧
    ∃gate_82, gate_82 = Gates.add gate_81 (RecipientPk.get (21 : Fin 65)) ∧
    ∃gate_83, gate_83 = Gates.mul gate_82 (256:F) ∧
    ∃gate_84, gate_84 = Gates.add gate_83 (RecipientPk.get (22 : Fin 65)) ∧
    ∃gate_85, gate_85 = Gates.mul gate_84 (256:F) ∧
    ∃gate_86, gate_86 = Gates.add gate_85 (RecipientPk.get (23 : Fin 65)) ∧
    ∃gate_87, gate_87 = Gates.mul gate_86 (256:F) ∧
    ∃gate_88, gate_88 = Gates.add gate_87 (RecipientPk.get (24 : Fin 65)) ∧
    ∃gate_89, gate_89 = Gates.mul (0:F) (256:F) ∧
    ∃gate_90, gate_90 = Gates.add gate_89 (RecipientPk.get (17 : Fin 65)) ∧
    ∃gate_91, gate_91 = Gates.mul gate_90 (256:F) ∧
    ∃gate_92, gate_92 = Gates.add gate_91 (RecipientPk.get (18 : Fin 65)) ∧
    ∃gate_93, gate_93 = Gates.mul gate_92 (256:F) ∧
    ∃gate_94, gate_94 = Gates.add gate_93 (RecipientPk.get (19 : Fin 65)) ∧
    ∃gate_95, gate_95 = Gates.mul gate_94 (256:F) ∧
    ∃gate_96, gate_96 = Gates.add gate_95 (RecipientPk.get (20 : Fin 65)) ∧
    ∃gate_97, gate_97 = Gates.mul (0:F) (256:F) ∧
    ∃gate_98, gate_98 = Gates.add gate_97 (RecipientPk.get (13 : Fin 65)) ∧
    ∃gate_99, gate_99 = Gates.mul gate_98 (256:F) ∧
    ∃gate_100, gate_100 = Gates.add gate_99 (RecipientPk.get (14 : Fin 65)) ∧
    ∃gate_101, gate_101 = Gates.mul gate_100 (256:F) ∧
    ∃gate_102, gate_102 = Gates.add gate_101 (RecipientPk.get (15 : Fin 65)) ∧
    ∃gate_103, gate_103 = Gates.mul gate_102 (256:F) ∧
    ∃gate_104, gate_104 = Gates.add gate_103 (RecipientPk.get (16 : Fin 65)) ∧
    ∃gate_105, gate_105 = Gates.mul (0:F) (256:F) ∧
    ∃gate_106, gate_106 = Gates.add gate_105 (RecipientPk.get (9 : Fin 65)) ∧
    ∃gate_107, gate_107 = Gates.mul gate_106 (256:F) ∧
    ∃gate_108, gate_108 = Gates.add gate_107 (RecipientPk.get (10 : Fin 65)) ∧
    ∃gate_109, gate_109 = Gates.mul gate_108 (256:F) ∧
    ∃gate_110, gate_110 = Gates.add gate_109 (RecipientPk.get (11 : Fin 65)) ∧
    ∃gate_111, gate_111 = Gates.mul gate_110 (256:F) ∧
    ∃gate_112, gate_112 = Gates.add gate_111 (RecipientPk.get (12 : Fin 65)) ∧
    ∃gate_113, gate_113 = Gates.mul (0:F) (256:F) ∧
    ∃gate_114, gate_114 = Gates.add gate_113 (RecipientPk.get (5 : Fin 65)) ∧
    ∃gate_115, gate_115 = Gates.mul gate_114 (256:F) ∧
    ∃gate_116, gate_116 = Gates.add gate_115 (RecipientPk.get (6 : Fin 65)) ∧
    ∃gate_117, gate_117 = Gates.mul gate_116 (256:F) ∧
    ∃gate_118, gate_118 = Gates.add gate_117 (RecipientPk.get (7 : Fin 65)) ∧
    ∃gate_119, gate_119 = Gates.mul gate_118 (256:F) ∧
    ∃gate_120, gate_120 = Gates.add gate_119 (RecipientPk.get (8 : Fin 65)) ∧
    ∃gate_121, gate_121 = Gates.mul (0:F) (256:F) ∧
    ∃gate_122, gate_122 = Gates.add gate_121 (RecipientPk.get (1 : Fin 65)) ∧
    ∃gate_123, gate_123 = Gates.mul gate_122 (256:F) ∧
    ∃gate_124, gate_124 = Gates.add gate_123 (RecipientPk.get (2 : Fin 65)) ∧
    ∃gate_125, gate_125 = Gates.mul gate_124 (256:F) ∧
    ∃gate_126, gate_126 = Gates.add gate_125 (RecipientPk.get (3 : Fin 65)) ∧
    ∃gate_127, gate_127 = Gates.mul gate_126 (256:F) ∧
    ∃gate_128, gate_128 = Gates.add gate_127 (RecipientPk.get (4 : Fin 65)) ∧
    ∃gate_129, gate_129 = Gates.mul (0:F) (256:F) ∧
    ∃gate_130, gate_130 = Gates.add gate_129 (RecipientPk.get (61 : Fin 65)) ∧
    ∃gate_131, gate_131 = Gates.mul gate_130 (256:F) ∧
    ∃gate_132, gate_132 = Gates.add gate_131 (RecipientPk.get (62 : Fin 65)) ∧
    ∃gate_133, gate_133 = Gates.mul gate_132 (256:F) ∧
    ∃gate_134, gate_134 = Gates.add gate_133 (RecipientPk.get (63 : Fin 65)) ∧
    ∃gate_135, gate_135 = Gates.mul gate_134 (256:F) ∧
    ∃gate_136, gate_136 = Gates.add gate_135 (RecipientPk.get (64 : Fin 65)) ∧
    ∃gate_137, gate_137 = Gates.mul (0:F) (256:F) ∧
    ∃gate_138, gate_138 = Gates.add gate_137 (RecipientPk.get (57 : Fin 65)) ∧
    ∃gate_139, gate_139 = Gates.mul gate_138 (256:F) ∧
    ∃gate_140, gate_140 = Gates.add gate_139 (RecipientPk.get (58 : Fin 65)) ∧
    ∃gate_141, gate_141 = Gates.mul gate_140 (256:F) ∧
    ∃gate_142, gate_142 = Gates.add gate_141 (RecipientPk.get (59 : Fin 65)) ∧
    ∃gate_143, gate_143 = Gates.mul gate_142 (256:F) ∧
    ∃gate_144, gate_144 = Gates.add gate_143 (RecipientPk.get (60 : Fin 65)) ∧
    ∃gate_145, gate_145 = Gates.mul (0:F) (256:F) ∧
    ∃gate_146, gate_146 = Gates.add gate_145 (RecipientPk.get (53 : Fin 65)) ∧
    ∃gate_147, gate_147 = Gates.mul gate_146 (256:F) ∧
    ∃gate_148, gate_148 = Gates.add gate_147 (RecipientPk.get (54 : Fin 65)) ∧
    ∃gate_149, gate_149 = Gates.mul gate_148 (256:F) ∧
    ∃gate_150, gate_150 = Gates.add gate_149 (RecipientPk.get (55 : Fin 65)) ∧
    ∃gate_151, gate_151 = Gates.mul gate_150 (256:F) ∧
    ∃gate_152, gate_152 = Gates.add gate_151 (RecipientPk.get (56 : Fin 65)) ∧
    ∃gate_153, gate_153 = Gates.mul (0:F) (256:F) ∧
    ∃gate_154, gate_154 = Gates.add gate_153 (RecipientPk.get (49 : Fin 65)) ∧
    ∃gate_155, gate_155 = Gates.mul gate_154 (256:F) ∧
    ∃gate_156, gate_156 = Gates.add gate_155 (RecipientPk.get (50 : Fin 65)) ∧
    ∃gate_157, gate_157 = Gates.mul gate_156 (256:F) ∧
    ∃gate_158, gate_158 = Gates.add gate_157 (RecipientPk.get (51 : Fin 65)) ∧
    ∃gate_159, gate_159 = Gates.mul gate_158 (256:F) ∧
    ∃gate_160, gate_160 = Gates.add gate_159 (RecipientPk.get (52 : Fin 65)) ∧
    ∃gate_161, gate_161 = Gates.mul (0:F) (256:F) ∧
    ∃gate_162, gate_162 = Gates.add gate_161 (RecipientPk.get (45 : Fin 65)) ∧
    ∃gate_163, gate_163 = Gates.mul gate_162 (256:F) ∧
    ∃gate_164, gate_164 = Gates.add gate_163 (RecipientPk.get (46 : Fin 65)) ∧
    ∃gate_165, gate_165 = Gates.mul gate_164 (256:F) ∧
    ∃gate_166, gate_166 = Gates.add gate_165 (RecipientPk.get (47 : Fin 65)) ∧
    ∃gate_167, gate_167 = Gates.mul gate_166 (256:F) ∧
    ∃gate_168, gate_168 = Gates.add gate_167 (RecipientPk.get (48 : Fin 65)) ∧
    ∃gate_169, gate_169 = Gates.mul (0:F) (256:F) ∧
    ∃gate_170, gate_170 = Gates.add gate_169 (RecipientPk.get (41 : Fin 65)) ∧
    ∃gate_171, gate_171 = Gates.mul gate_170 (256:F) ∧
    ∃gate_172, gate_172 = Gates.add gate_171 (RecipientPk.get (42 : Fin 65)) ∧
    ∃gate_173, gate_173 = Gates.mul gate_172 (256:F) ∧
    ∃gate_174, gate_174 = Gates.add gate_173 (RecipientPk.get (43 : Fin 65)) ∧
    ∃gate_175, gate_175 = Gates.mul gate_174 (256:F) ∧
    ∃gate_176, gate_176 = Gates.add gate_175 (RecipientPk.get (44 : Fin 65)) ∧
    ∃gate_177, gate_177 = Gates.mul (0:F) (256:F) ∧
    ∃gate_178, gate_178 = Gates.add gate_177 (RecipientPk.get (37 : Fin 65)) ∧
    ∃gate_179, gate_179 = Gates.mul gate_178 (256:F) ∧
    ∃gate_180, gate_180 = Gates.add gate_179 (RecipientPk.get (38 : Fin 65)) ∧
    ∃gate_181, gate_181 = Gates.mul gate_180 (256:F) ∧
    ∃gate_182, gate_182 = Gates.add gate_181 (RecipientPk.get (39 : Fin 65)) ∧
    ∃gate_183, gate_183 = Gates.mul gate_182 (256:F) ∧
    ∃gate_184, gate_184 = Gates.add gate_183 (RecipientPk.get (40 : Fin 65)) ∧
    ∃gate_185, gate_185 = Gates.mul (0:F) (256:F) ∧
    ∃gate_186, gate_186 = Gates.add gate_185 (RecipientPk.get (33 : Fin 65)) ∧
    ∃gate_187, gate_187 = Gates.mul gate_186 (256:F) ∧
    ∃gate_188, gate_188 = Gates.add gate_187 (RecipientPk.get (34 : Fin 65)) ∧
    ∃gate_189, gate_189 = Gates.mul gate_188 (256:F) ∧
    ∃gate_190, gate_190 = Gates.add gate_189 (RecipientPk.get (35 : Fin 65)) ∧
    ∃gate_191, gate_191 = Gates.mul gate_190 (256:F) ∧
    ∃gate_192, gate_192 = Gates.add gate_191 (RecipientPk.get (36 : Fin 65)) ∧
    AssertCanonical_8_0_hcc2f8a19 vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] ∧
    AssertCanonical_8_0_hcc2f8a19 vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] ∧
    AssertOnCurve_8_8_h2c0228bb vec![gate_72, gate_80, gate_88, gate_96, gate_104, gate_112, gate_120, gate_128] vec![gate_136, gate_144, gate_152, gate_160, gate_168, gate_176, gate_184, gate_192] ∧
    SplitLowBits_1_8 (RecipientPk.get (64 : Fin 65)) fun gate_196 =>
    ∃gate_197, gate_197 = Gates.add (2:F) (gate_196.get (1 : Fin 2)) ∧
    ∃gate_198, gate_198 = Gates.mul gate_197 K_0 ∧
    ∃gate_199, gate_199 = Gates.mul (0:F) (256:F) ∧
    EnvelopeMerge_32_65_40_4_p1 EphemeralSk RecipientPk Plaintext Context Elements Blinding gate_72 gate_80 gate_88 gate_96 gate_104 gate_112 gate_120 gate_128 gate_136 gate_144 gate_152 gate_160 gate_168 gate_176 gate_184 gate_192 gate_198 gate_199

end ZolanaVE
