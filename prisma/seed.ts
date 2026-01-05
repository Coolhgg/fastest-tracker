import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'

const prisma = new PrismaClient()
const SALT_ROUNDS = 12

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS)
}

async function main() {
  console.log('Start seeding...')

  // Clear existing data to avoid conflicts on re-run
  // Using a specific order to respect foreign key constraints
  await prisma.activity.deleteMany({})
  await prisma.notification.deleteMany({})
  await prisma.libraryEntry.deleteMany({})
  await prisma.chapter.deleteMany({})
  await prisma.seriesSource.deleteMany({})
  await prisma.series.deleteMany({})
  await prisma.userAchievement.deleteMany({})
  await prisma.achievement.deleteMany({})
  await prisma.follow.deleteMany({})
  // Note: We don't delete users to avoid breaking Auth session links
  // If you need to clear users, do it manually in the DB or add it here

  // 1. Create Achievements
  const achievements = [
    {
      code: 'first_chapter',
      name: 'First Steps',
      description: 'Read your first chapter',
      xp_reward: 50,
      rarity: 'common',
      criteria: { type: 'chapter_count', threshold: 1 }
    },
    {
      code: 'speed_reader',
      name: 'Speed Reader',
      description: 'Read 100 chapters',
      xp_reward: 200,
      rarity: 'rare',
      criteria: { type: 'chapter_count', threshold: 100 }
    },
    {
      code: 'completionist',
      name: 'Completionist',
      description: 'Complete your first series',
      xp_reward: 500,
      rarity: 'epic',
      criteria: { type: 'completed_count', threshold: 1 }
    },
    {
      code: 'social_butterfly',
      name: 'Social Butterfly',
      description: 'Follow 10 other readers',
      xp_reward: 100,
      rarity: 'common',
      criteria: { type: 'follow_count', threshold: 10 }
    },
    {
      code: 'collector',
      name: 'The Collector',
      description: 'Add 50 series to your library',
      xp_reward: 300,
      rarity: 'rare',
      criteria: { type: 'library_count', threshold: 50 }
    }
  ]

  for (const ach of achievements) {
    await prisma.achievement.upsert({
      where: { code: ach.code },
      update: ach,
      create: ach,
    })
  }
  console.log('✅ Achievements seeded.')

  // 2. Create Sample Series
  const seriesData = [
    {
      title: "Solo Leveling",
      description: "In a world where hunters, humans who possess magical abilities, must battle deadly monsters to protect the human race from certain annihilation, a notoriously weak hunter named Sung Jinwoo finds himself in a seemingly endless struggle for survival.",
      type: "manhwa",
      status: "completed",
      cover_url: "https://images.unsplash.com/photo-1618336753974-aae8e04506aa?q=80&w=400&auto=format&fit=crop",
      genres: ["Action", "Fantasy", "Adventure"],
      total_follows: 450000,
      alternative_titles: ["Only I Level Up", "Na Honjaman Level Up"],
    },
    {
      title: "One Piece",
      description: "Monkey D. Luffy refuses to let anyone or anything stand in the way of his quest to become the king of all pirates. With a course charted for the treacherous waters of the Grand Line and beyond, this is one captain who'll never give up until he's claimed the greatest treasure on Earth: the Legendary One Piece!",
      type: "manga",
      status: "ongoing",
      cover_url: "https://images.unsplash.com/photo-1580477667995-2b94f01c9516?q=80&w=400&auto=format&fit=crop",
      genres: ["Action", "Adventure", "Comedy", "Fantasy"],
      total_follows: 850000,
      alternative_titles: ["OP"],
    },
    {
      title: "Berserk",
      description: "Guts, a former mercenary now known as the 'Black Swordsman,' is out for revenge. After a tumultuous childhood, he finally finds someone he respects and believes he can trust, only to have everything fall apart when this person sacrifices everything he's ever cared for for his own desires.",
      type: "manga",
      status: "ongoing",
      cover_url: "https://images.unsplash.com/photo-1516466723877-e4ec1d736c8a?q=80&w=400&auto=format&fit=crop",
      genres: ["Action", "Dark Fantasy", "Horror", "Seinen"],
      total_follows: 280000,
    },
    {
      title: "The Beginning After The End",
      description: "King Grey has unrivaled strength, wealth, and prestige in a world governed by martial ability. However, solitude lingers closely behind those with great power. Beneath the glamorous exterior of a powerful king lurks the shell of man, devoid of purpose and will.",
      type: "manhwa",
      status: "ongoing",
      cover_url: "https://images.unsplash.com/photo-1612178537253-bccd437b730e?q=80&w=400&auto=format&fit=crop",
      genres: ["Action", "Fantasy", "Adventure", "Isekai"],
      total_follows: 150000,
    },
    {
      title: "Tower of God",
      description: "What do you desire? Fortune? Glory? Power? Revenge? Or something that surpasses all others? Whatever you desire, 'it' is here. Tower of God.",
      type: "manhwa",
      status: "ongoing",
      cover_url: "https://images.unsplash.com/photo-1607604276583-eef5d076aa5f?q=80&w=400&auto=format&fit=crop",
      genres: ["Action", "Adventure", "Mystery", "Drama"],
      total_follows: 320000,
      alternative_titles: ["Kami no Tou", "Sin-ui Tap"],
    }
  ]

  for (const s of seriesData) {
    const createdSeries = await prisma.series.create({
      data: s
    })

    // Add multiple sources for some series
    const sources = [
      { name: 'mangadex', priority: 'HOT' },
      { name: 'mangatown', priority: 'WARM' }
    ]

    for (const source of sources) {
      const createdSource = await prisma.seriesSource.create({
        data: {
          series_id: createdSeries.id,
          source_name: source.name,
          source_id: `${source.name.slice(0, 2)}-${createdSeries.id.slice(0, 8)}`,
          source_url: `https://${source.name}.com/title/${createdSeries.id}`,
          trust_score: source.name === 'mangadex' ? 9.5 : 7.0,
          sync_priority: source.priority,
          source_chapter_count: 100,
        }
      })

      // Add sample chapters for the first source
      if (source.name === 'mangadex') {
        for (let i = 1; i <= 5; i++) {
          await prisma.chapter.create({
            data: {
              series_id: createdSeries.id,
              series_source_id: createdSource.id,
              chapter_number: i,
              chapter_title: `Chapter ${i}`,
              chapter_url: `${createdSource.source_url}/chapter/${i}`,
              published_at: new Date(Date.now() - (6 - i) * 24 * 60 * 60 * 1000)
            }
          })
        }
      }
    }
  }
  console.log('✅ Series, Sources, and Chapters seeded.')

  console.log('🏁 Seeding finished successfully.')
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
