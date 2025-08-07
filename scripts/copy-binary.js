const fs = require('fs')
const path = require('path')
const os = require('os')

const packageJson = require('../package.json')

// binary 정보 추출
const binary = packageJson.binary
const moduleName = binary.module_name
const platform = os.platform()
const arch = os.arch()

const source = path.resolve(__dirname, `../build/Release/${moduleName}.node`)
const targetDir = path.resolve(
  __dirname,
  `../${binary.module_path}`
    .replace('{platform}', platform)
    .replace('{arch}', arch)
)
const target = path.join(targetDir, `${moduleName}.node`)

// 복사 실행
try {
  fs.mkdirSync(targetDir, { recursive: true })
  fs.copyFileSync(source, target)
} catch (e) {
  console.error(e)
}

console.log(`[postrebuild] Copied:\n  ${source} →\n  ${target}`)
