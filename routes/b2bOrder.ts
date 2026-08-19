/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      if (!isSafeOrderLinesData(orderLinesData)) {
        res.status(400)
        next(new Error('Blocked by security policy'))
        return
      }
      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function isSafeOrderLinesData (data: unknown): boolean {
    if (typeof data !== 'string') {
      return false
    }
    // Block dangerous characters that can be used for obfuscation or escaping
    if (data.includes('\\') || data.includes('`') || data.includes('+')) {
      return false
    }

    // Block dangerous words (case-insensitive)
    const lowerData = data.toLowerCase()
    const bannedWords = [
      'process',
      'require',
      'child_process',
      'exec',
      'spawn',
      'fs',
      'import',
      'global',
      'globalthis',
      'mainmodule',
      'module',
      'exports',
      '__filename',
      '__dirname',
      'concat',
      'join',
      'slice',
      'substring',
      'substr',
      'replace',
      'fromcharcode',
      'string',
      'buffer',
      'object',
      'reflect',
      'proxy',
      'symbol',
      'eval',
      'function',
      'callee',
      'caller'
    ]

    for (const word of bannedWords) {
      if (lowerData.includes(word)) {
        return false
      }
    }

    return true
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
