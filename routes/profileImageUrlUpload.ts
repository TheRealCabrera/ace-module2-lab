/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import net from 'node:net'
import dns from 'node:dns/promises'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) {
      return true
    }
    const [a, b, c, d] = parts
    if (a === 127) return true
    if (a === 10) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 169 && b === 254) return true
    if (a === 0) return true
    if (a === 255 && b === 255 && c === 255 && d === 255) return true
    return false
  } else if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase()
    if (normalized === '::1' || normalized === '::') return true
    if (normalized.startsWith('::ffff:')) {
      const mappedIp = ip.substring(7)
      return isPrivateIp(mappedIp)
    }
    const firstWord = normalized.split(':')[0]
    if (firstWord) {
      const firstWordHex = parseInt(firstWord, 16)
      if (!isNaN(firstWordHex)) {
        if ((firstWordHex & 0xfe00) === 0xfc00) return true
        if ((firstWordHex & 0xffc0) === 0xfe80) return true
      }
    }
    return false
  }
  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        let parsedUrl: URL
        try {
          parsedUrl = new URL(url)
        } catch (err) {
          next(new Error('Invalid URL format'))
          return
        }

        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
          next(new Error('Only http and https protocols are allowed'))
          return
        }

        const hostname = parsedUrl.hostname
        if (!hostname) {
          next(new Error('Invalid hostname'))
          return
        }

        try {
          const lookupResults = await dns.lookup(hostname, { all: true })
          for (const entry of lookupResults) {
            if (isPrivateIp(entry.address)) {
              next(new Error('Access to private or local network addresses is forbidden'))
              return
            }
          }
        } catch (dnsErr) {
          next(new Error('Could not resolve hostname'))
          return
        }

        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
