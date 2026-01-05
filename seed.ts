
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
)

const seriesData = [
  {
    title: "Solo Leveling",
    description: "Ten years ago, after the Gate that connected the real world with the monster world opened, some of the ordinary, everyday people received the power to hunt monsters within the Gate. They are known as Hunters.",
    type: "manhwa",
    status: "completed",
    cover_url: "https://images.unsplash.com/photo-1618336753974-aae8e04506aa?q=80&w=400&auto=format&fit=crop",
    genres: ["Action", "Fantasy", "Adventure"],
    total_follows: 450000,
    average_rating: 9.1
  },
  {
    title: "One Piece",
    description: "Monkey D. Luffy refuses to let anyone or anything stand in the way of his quest to become the king of all pirates. With a course charted for the treacherous waters of the Grand Line and beyond, this is one captain who'll never give up until he's claimed the greatest treasure on Earth—the Legendary One Piece!",
    type: "manga",
    status: "ongoing",
    cover_url: "https://images.unsplash.com/photo-1580477667995-2b94f01c9516?q=80&w=400&auto=format&fit=crop",
    genres: ["Action", "Adventure", "Comedy"],
    total_follows: 850000,
    average_rating: 9.5
  },
  {
    title: "Tower of God",
    description: "What do you desire? Fortune? Glory? Power? Revenge? Or something that surpasses all others? Whatever you desire, 'it' is here. Tower of God.",
    type: "webtoon",
    status: "ongoing",
    cover_url: "https://images.unsplash.com/photo-1608889175123-8ee362201f81?q=80&w=400&auto=format&fit=crop",
    genres: ["Fantasy", "Action", "Drama"],
    total_follows: 320000,
    average_rating: 8.8
  },
  {
    title: "Berserk",
    description: "Guts, a former mercenary now known as the 'Black Swordsman,' is out for revenge. After a tumultuous childhood, he finally finds someone he respects and believes he can trust, only to have everything fall apart when this person takes away everything important to Guts for the sake of fulfilling his own desires.",
    type: "manga",
    status: "ongoing",
    cover_url: "https://images.unsplash.com/photo-1516466723877-e4ec1d736c8a?q=80&w=400&auto=format&fit=crop",
    genres: ["Action", "Dark Fantasy", "Horror"],
    total_follows: 280000,
    average_rating: 9.8
  },
  {
    title: "Omniscient Reader",
    description: "'This is a story that I know.' At that moment, the world was destroyed, and a new universe unfolded. The new life of an ordinary reader begins within the world of the novel, a novel that he alone has finished.",
    type: "manhwa",
    status: "ongoing",
    cover_url: "https://images.unsplash.com/photo-1541963463532-d68292c34b19?q=80&w=400&auto=format&fit=crop",
    genres: ["Action", "Fantasy", "Psychological"],
    total_follows: 210000,
    average_rating: 9.3
  }
]

async function seed() {
  console.log('Seeding data...')
  
  for (const series of seriesData) {
    const { data: existingSeries } = await supabase
      .from('series')
      .select('id')
      .eq('title', series.title)
      .maybeSingle()

    let seriesId;
    if (existingSeries) {
      seriesId = existingSeries.id
      console.log('Series already exists:', series.title)
    } else {
      const { data, error } = await supabase
        .from('series')
        .insert(series)
        .select()
        .single()
      
      if (error) {
        console.error('Error seeding series:', error.message)
        continue
      }
      seriesId = data.id
      console.log('Seeded series:', data.title)
    }
    
    // Check for existing source
    const { data: existingSource } = await supabase
      .from('series_sources')
      .select('id')
      .eq('series_id', seriesId)
      .eq('source_name', 'mangadex')
      .maybeSingle()

    let seriesSourceId;
    if (existingSource) {
      seriesSourceId = existingSource.id
      console.log('Source already exists for:', series.title)
    } else {
      const { data, error } = await supabase
        .from('series_sources')
        .insert({
          series_id: seriesId,
          source_name: 'mangadex',
          source_id: 'md-' + seriesId.slice(0, 8),
          source_url: 'https://mangadex.org/title/' + seriesId,
          trust_score: 9.0
        })
        .select()
        .single()

      if (error) {
        console.error(`Error seeding source for ${series.title}:`, error.message)
        continue
      }
      seriesSourceId = data.id
      console.log('Seeded source for:', series.title)
    }

    // Seed Chapters
    const now = new Date()
    for (let i = 1; i <= 5; i++) {
      const chapterNum = 100 + i
      
      const { data: existingChapter } = await supabase
        .from('chapters')
        .select('id')
        .eq('series_id', seriesId)
        .eq('chapter_number', chapterNum)
        .maybeSingle()

      if (existingChapter) {
        console.log(`Chapter ${chapterNum} already exists for ${series.title}`)
        continue
      }

      const discoveredAt = new Date(now)
      discoveredAt.setDate(now.getDate() - (5 - i))
      
      const { error: chError } = await supabase
        .from('chapters')
        .insert({
          series_id: seriesId,
          series_source_id: seriesSourceId,
          chapter_number: chapterNum,
          chapter_title: `Chapter ${chapterNum}`,
          chapter_url: `https://mangadex.org/chapter/${i}`,
          published_at: discoveredAt.toISOString(),
          discovered_at: discoveredAt.toISOString()
        })
      
      if (chError) {
        console.error(`Error seeding chapter ${chapterNum} for ${series.title}:`, chError.message)
      } else {
        console.log(`Seeded chapter ${chapterNum} for ${series.title}`)
      }
    }
  }

  // Seed Achievements
  const achievements = [
    { code: 'first_chapter', name: 'First Steps', description: 'Read your first chapter', xp_reward: 50, rarity: 'common', criteria: { type: 'chapter_count', threshold: 1 } },
    { code: 'speed_reader', name: 'Speed Reader', description: 'Read 100 chapters', xp_reward: 200, rarity: 'rare', criteria: { type: 'chapter_count', threshold: 100 } },
    { code: 'completionist', name: 'Completionist', description: 'Complete your first series', xp_reward: 500, rarity: 'epic', criteria: { type: 'completed_count', threshold: 1 } }
  ]

  for (const ach of achievements) {
    await supabase
      .from('achievements')
      .upsert(ach, { onConflict: 'code' })
  }

  console.log('Seeding complete.')
}

seed()
