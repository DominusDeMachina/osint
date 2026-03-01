import { defineConfig } from 'orval'

export default defineConfig({
  osint: {
    input: {
      target: 'http://localhost:8000/api/v1/openapi.json',
    },
    output: {
      mode: 'tags-split',
      target: './src/api/generated',
      schemas: './src/api/generated/schemas',
      client: 'react-query',
      httpClient: 'axios',
      clean: true,
      prettier: true,
    },
    hooks: {
      afterAllFilesWrite: 'prettier --write',
    },
  },
})
