/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  const cleanIp = ip.replace(/^\[|\]$/g, '')
  const ipv4Parts = cleanIp.split('.').map(Number)
  if (ipv4Parts.length === 4 && ipv4Parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
    const [p0, p1, p2] = ipv4Parts
    if (p0 === 0 || p0 === 10 || p0 === 127) return true
    if (p0 === 169 && p1 === 254) return true
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return true
    if (p0 === 192 && p1 === 168) return true
    if (p0 === 100 && p1 >= 64 && p1 <= 127) return true
    if (p0 === 192 && p1 === 0 && p2 === 2) return true
    if (p0 === 198 && p1 === 51 && p2 === 100) return true
    if (p0 === 203 && p1 === 0 && p2 === 113) return true
    if (p0 >= 224) return true
    return false
  }

  const lower = cleanIp.toLowerCase()
  if (
    lower === '::1' ||
    lower === '::' ||
    lower === '0:0:0:0:0:0:0:1' ||
    lower === '0:0:0:0:0:0:0:0' ||
    lower.startsWith('fe8') ||
    lower.startsWith('fe9') ||
    lower.startsWith('fea') ||
    lower.startsWith('feb') ||
    lower.startsWith('fc') ||
    lower.startsWith('fd')
  ) {
    return true
  }
  if (lower.startsWith('::ffff:') || lower.startsWith('0:0:0:0:0:ffff:')) {
    const embedded = lower.replace(/^.*ffff:/, '')
    if (embedded.includes('.')) {
      return isPrivateIp(embedded)
    }
    return true
  }

  return false
}

function isSafeUrl (urlString: string): boolean {
  if (typeof urlString !== 'string' || !urlString.trim()) {
    return false
  }
  let parsed: URL
  try {
    parsed = new URL(urlString)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }

  const hostname = parsed.hostname.toLowerCase()
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.home.arpa')
  ) {
    return false
  }

  if (isPrivateIp(hostname)) {
    return false
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url === 'string' && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!isSafeUrl(url)) {
          res.status(400)
          next(new Error('Unacceptable image URL'))
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
