/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: "node",
  testMatch: ["<rootDir>/__tests__/**/*.test.[jt]s"],
  transform: {
    "^.+\\.tsx?$": ["ts-jest", { tsconfig: "tsconfig.json" }],
  },
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
  modulePathIgnorePatterns: [
    "<rootDir>/.next",
    "<rootDir>/coverage",
    "<rootDir>/dist",
    "<rootDir>/node_modules",
  ],
  coverageDirectory: "coverage",
  reporters: ["default"],
};
