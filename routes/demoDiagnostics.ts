/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { exec } from 'child_process'

export function pingHost () {
  return ({ query }: Request, res: Response) => {
    const host = query.host as string
    exec(`ping -c 1 ${host}`, (error, stdout) => {
      if (error != null) {
        res.status(500).send(error.message)
        return
      }
      res.send(stdout)
    })
  }
}
