"use client"

interface ExternalLinkButtonProps {
  url: string
  children: React.ReactNode
  className?: string
}

export function ExternalLinkButton({ url, children, className }: ExternalLinkButtonProps) {
  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault()
    window.parent.postMessage({ 
      type: "OPEN_EXTERNAL_URL", 
      data: { url } 
    }, "*")
  }

  return (
    <button onClick={handleClick} className={className}>
      {children}
    </button>
  )
}

interface SourceCardProps {
  sourceUrl: string
  children: React.ReactNode
  className?: string
}

export function SourceCard({ sourceUrl, children, className }: SourceCardProps) {
  const handleClick = () => {
    window.parent.postMessage({ 
      type: "OPEN_EXTERNAL_URL", 
      data: { url: sourceUrl } 
    }, "*")
  }

  return (
    <div onClick={handleClick} className={className}>
      {children}
    </div>
  )
}
