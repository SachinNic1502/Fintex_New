module.exports = {
  // Run tests from one of these patterns
  testMatch: ['**/test/**/*.test.js'],
  
  // A map from regular expressions to paths to transformers
  transform: {
    '^.+\\.js$': 'babel-jest',
  },
  
  // Automatically clear mock calls and instances between every test
  clearMocks: true,
  
  // The directory where Jest should output its coverage files
  coverageDirectory: 'coverage',
  
  // An array of directory names to be searched recursively up from the requiring module's location
  moduleDirectories: ['node_modules', 'src'],
  
  // A map from regular expressions to module names that allow to stub out resources with a single module
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  
  // A list of paths to modules that run some code to configure or set up the testing framework before each test
  setupFilesAfterEnv: ['<rootDir>/test/setup.js'],
  
  // The test environment that will be used for testing
  testEnvironment: 'node',
  
  // An array of regexp pattern strings that are matched against all test paths, matched tests are skipped
  testPathIgnorePatterns: ['/node_modules/'],
  
  // This option sets the URL for the jsdom environment
  testURL: 'http://localhost',
  
  // A map from regular expressions to paths to transformers
  transformIgnorePatterns: ['/node_modules/'],
  
  // Indicates whether each individual test should be reported during the run
  verbose: true,
};
