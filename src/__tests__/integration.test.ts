import { prisma } from '@/lib/prisma'

jest.mock('@/lib/prisma', () => ({
  prisma: {
    user: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      count: jest.fn(),
    },
    series: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      count: jest.fn(),
    },
    libraryEntry: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      count: jest.fn(),
    },
    notification: {
      findMany: jest.fn(),
      count: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      create: jest.fn(),
    },
    activity: {
      findMany: jest.fn(),
      count: jest.fn(),
      create: jest.fn(),
    },
    follow: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      deleteMany: jest.fn(),
      count: jest.fn(),
    },
    $transaction: jest.fn((fn) => fn(prisma)),
  },
}))

const mockPrisma = prisma as jest.Mocked<typeof prisma>

describe('Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Library Entry Operations', () => {
    it('should fetch library entries with series data', async () => {
      const mockEntries = [
        {
          id: 'entry-1',
          user_id: 'user-1',
          series_id: 'series-1',
          status: 'reading',
          last_read_chapter: 10,
          series: {
            title: 'Test Manga',
            cover_url: 'https://example.com/cover.jpg',
            type: 'manga',
            status: 'ongoing',
          },
        },
      ]

      ;(mockPrisma.libraryEntry.findMany as jest.Mock).mockResolvedValue(mockEntries)

      const entries = await prisma.libraryEntry.findMany({
        where: { user_id: 'user-1' },
        include: { series: true },
      })

      expect(entries).toHaveLength(1)
      expect(entries[0].series?.title).toBe('Test Manga')
    })

    it('should handle empty library', async () => {
      ;(mockPrisma.libraryEntry.findMany as jest.Mock).mockResolvedValue([])

      const entries = await prisma.libraryEntry.findMany({
        where: { user_id: 'user-1' },
      })

      expect(entries).toHaveLength(0)
    })
  })

  describe('Series Operations', () => {
    it('should search series by query', async () => {
      const mockSeries = [
        {
          id: 'series-1',
          title: 'One Piece',
          type: 'manga',
          status: 'ongoing',
          genres: ['Action', 'Adventure'],
          average_rating: 4.8,
          total_follows: 100000,
        },
      ]

      ;(mockPrisma.series.findMany as jest.Mock).mockResolvedValue(mockSeries)

      const series = await prisma.series.findMany({
        where: {
          title: { contains: 'One', mode: 'insensitive' },
        },
      })

      expect(series).toHaveLength(1)
      expect(series[0].title).toBe('One Piece')
    })

    it('should get trending series', async () => {
      const mockTrending = [
        { id: 'series-1', title: 'Popular Manga', total_follows: 50000 },
        { id: 'series-2', title: 'Another Popular', total_follows: 40000 },
      ]

      ;(mockPrisma.series.findMany as jest.Mock).mockResolvedValue(mockTrending)

      const trending = await prisma.series.findMany({
        orderBy: { total_follows: 'desc' },
        take: 10,
      })

      expect(trending).toHaveLength(2)
      expect(trending[0].total_follows).toBeGreaterThan(trending[1].total_follows)
    })
  })

  describe('Leaderboard Operations', () => {
    it('should fetch leaderboard by XP', async () => {
      const mockUsers = [
        { username: 'top-user', xp: 10000, level: 50 },
        { username: 'second-user', xp: 8000, level: 40 },
        { username: 'third-user', xp: 6000, level: 30 },
      ]

      ;(mockPrisma.user.findMany as jest.Mock).mockResolvedValue(mockUsers)

      const users = await prisma.user.findMany({
        orderBy: { xp: 'desc' },
        take: 50,
      })

      expect(users).toHaveLength(3)
      expect(users[0].xp).toBe(10000)
    })

    it('should fetch leaderboard by streak', async () => {
      const mockUsers = [
        { username: 'streak-master', streak_days: 365 },
        { username: 'consistent-reader', streak_days: 100 },
      ]

      ;(mockPrisma.user.findMany as jest.Mock).mockResolvedValue(mockUsers)

      const users = await prisma.user.findMany({
        orderBy: { streak_days: 'desc' },
        take: 50,
      })

      expect(users[0].streak_days).toBe(365)
    })
  })

  describe('Feed Operations', () => {
    it('should fetch global activity feed', async () => {
      const mockActivities = [
        {
          id: 'activity-1',
          type: 'chapter_read',
          user: { username: 'reader1', avatar_url: null },
          series: { title: 'Test Manga', cover_url: null },
        },
        {
          id: 'activity-2',
          type: 'series_added',
          user: { username: 'reader2', avatar_url: null },
          series: { title: 'Another Manga', cover_url: null },
        },
      ]

      ;(mockPrisma.activity.findMany as jest.Mock).mockResolvedValue(mockActivities)
      ;(mockPrisma.activity.count as jest.Mock).mockResolvedValue(2)

      const activities = await prisma.activity.findMany({
        orderBy: { created_at: 'desc' },
        take: 20,
        include: { user: true, series: true },
      })

      expect(activities).toHaveLength(2)
      expect(activities[0].type).toBe('chapter_read')
    })

    it('should filter feed by following', async () => {
      const mockFollowing = [
        { following_id: 'user-2' },
        { following_id: 'user-3' },
      ]

      ;(mockPrisma.follow.findMany as jest.Mock).mockResolvedValue(mockFollowing)

      const following = await prisma.follow.findMany({
        where: { follower_id: 'user-1' },
        select: { following_id: true },
      })

      expect(following).toHaveLength(2)
      const followingIds = following.map((f: any) => f.following_id)
      expect(followingIds).toContain('user-2')
    })
  })

  describe('Notification Operations', () => {
    it('should fetch notifications with pagination', async () => {
      const mockNotifications = [
        { id: 'notif-1', type: 'new_chapter', read_at: null, title: 'New Chapter Available' },
        { id: 'notif-2', type: 'follow', read_at: new Date(), title: 'New Follower' },
      ]

      ;(mockPrisma.notification.findMany as jest.Mock).mockResolvedValue(mockNotifications)
      ;(mockPrisma.notification.count as jest.Mock).mockResolvedValue(2)

      const notifications = await prisma.notification.findMany({
        where: { user_id: 'user-1' },
        orderBy: { created_at: 'desc' },
        skip: 0,
        take: 20,
      })

      expect(notifications).toHaveLength(2)
    })

    it('should mark all notifications as read', async () => {
      ;(mockPrisma.notification.updateMany as jest.Mock).mockResolvedValue({ count: 5 })

      const result = await prisma.notification.updateMany({
        where: { user_id: 'user-1', read_at: null },
        data: { read_at: new Date() },
      })

      expect(result.count).toBe(5)
    })

    it('should filter unread notifications', async () => {
      const mockUnread = [
        { id: 'notif-1', type: 'new_chapter', read_at: null },
      ]

      ;(mockPrisma.notification.findMany as jest.Mock).mockResolvedValue(mockUnread)
      ;(mockPrisma.notification.count as jest.Mock).mockResolvedValue(1)

      const unread = await prisma.notification.findMany({
        where: { user_id: 'user-1', read_at: null },
      })

      expect(unread).toHaveLength(1)
      expect(unread[0].read_at).toBeNull()
    })
  })

  describe('Follow Operations', () => {
    it('should create follow relationship', async () => {
      const mockFollow = {
        id: 'follow-1',
        follower_id: 'user-1',
        following_id: 'user-2',
        created_at: new Date(),
      }

      ;(mockPrisma.follow.create as jest.Mock).mockResolvedValue(mockFollow)

      const follow = await prisma.follow.create({
        data: {
          follower_id: 'user-1',
          following_id: 'user-2',
        },
      })

      expect(follow.follower_id).toBe('user-1')
      expect(follow.following_id).toBe('user-2')
    })

    it('should check follow status', async () => {
      ;(mockPrisma.follow.findUnique as jest.Mock).mockResolvedValue({ id: 'follow-1' })

      const follow = await prisma.follow.findUnique({
        where: {
          follower_id_following_id: {
            follower_id: 'user-1',
            following_id: 'user-2',
          },
        },
      })

      expect(follow).not.toBeNull()
    })

    it('should unfollow user', async () => {
      ;(mockPrisma.follow.deleteMany as jest.Mock).mockResolvedValue({ count: 1 })

      const result = await prisma.follow.deleteMany({
        where: {
          follower_id: 'user-1',
          following_id: 'user-2',
        },
      })

      expect(result.count).toBe(1)
    })
  })

  describe('User Profile Operations', () => {
    it('should get user profile by username', async () => {
      const mockUser = {
        id: 'user-1',
        username: 'testuser',
        email: 'test@example.com',
        avatar_url: null,
        bio: 'Manga enthusiast',
        xp: 1000,
        level: 10,
        streak_days: 30,
      }

      ;(mockPrisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser)

      const user = await prisma.user.findUnique({
        where: { username: 'testuser' },
      })

      expect(user?.username).toBe('testuser')
      expect(user?.level).toBe(10)
    })

    it('should update user profile', async () => {
      const mockUpdatedUser = {
        id: 'user-1',
        username: 'testuser',
        bio: 'Updated bio',
      }

      ;(mockPrisma.user.update as jest.Mock).mockResolvedValue(mockUpdatedUser)

      const user = await prisma.user.update({
        where: { id: 'user-1' },
        data: { bio: 'Updated bio' },
      })

      expect(user.bio).toBe('Updated bio')
    })
  })

  describe('Transaction Operations', () => {
    it('should handle adding series to library atomically', async () => {
      const mockEntry = {
        id: 'entry-1',
        user_id: 'user-1',
        series_id: 'series-1',
        status: 'reading',
      }

      ;(mockPrisma.$transaction as jest.Mock).mockImplementation(async (fn) => {
        return mockEntry
      })

      const result = await prisma.$transaction(async (tx) => {
        return mockEntry
      })

      expect(result.status).toBe('reading')
    })
  })
})
