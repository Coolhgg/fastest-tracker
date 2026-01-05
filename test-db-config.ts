import { Client } from 'pg'

async function main() {
  const client = new Client({
    user: 'postgres.nkrxhoamqsawixdwehaq',
    host: 'aws-1-us-east-2.pooler.supabase.com',
    database: 'postgres',
    password: 'hg2604207599980520',
    port: 5432,
  })

  try {
    await client.connect()
    console.log('Connection successful with raw password!')
    const res = await client.query('SELECT 1')
    console.log('Query result:', res.rows)
  } catch (err) {
    console.error('Connection failed with raw password:', err.message)
  } finally {
    await client.end()
  }
}

main()
