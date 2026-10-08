#pragma once

// Фиксированный регион vDSO в адресном пространстве каждого процесса.
// Страницы ниже текста vDSO читает сам vdso.c по этим константам.
#define NOMILIA_VDSO_CLOCK_PAGE 0x700000000000UL
#define NOMILIA_VDSO_TRACK_PAGE 0x700000001000UL
#define NOMILIA_VDSO_TEXT_BASE 0x700000002000UL
